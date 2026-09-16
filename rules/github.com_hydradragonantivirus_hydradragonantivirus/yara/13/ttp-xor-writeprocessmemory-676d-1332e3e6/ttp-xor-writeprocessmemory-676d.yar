rule TTP_XOR_WriteProcessMemory_676d {
  strings:
    $key_676d = { 30 1f [2] 02 3d [2] 04 08 [2] 2a 08 [2] 15 14 }

  condition:
    any of them
}