rule TTP_XOR_WriteProcessMemory_4d6d {
  strings:
    $key_4d6d = { 1a 1f [2] 28 3d [2] 2e 08 [2] 00 08 [2] 3f 14 }

  condition:
    any of them
}