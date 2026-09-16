rule TTP_XOR_WriteProcessMemory_836d {
  strings:
    $key_836d = { d4 1f [2] e6 3d [2] e0 08 [2] ce 08 [2] f1 14 }

  condition:
    any of them
}