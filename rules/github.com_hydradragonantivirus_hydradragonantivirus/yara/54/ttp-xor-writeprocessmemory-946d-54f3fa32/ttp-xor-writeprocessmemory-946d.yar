rule TTP_XOR_WriteProcessMemory_946d {
  strings:
    $key_946d = { c3 1f [2] f1 3d [2] f7 08 [2] d9 08 [2] e6 14 }

  condition:
    any of them
}