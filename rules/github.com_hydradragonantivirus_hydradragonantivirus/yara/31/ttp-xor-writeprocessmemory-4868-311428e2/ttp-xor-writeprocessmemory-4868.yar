rule TTP_XOR_WriteProcessMemory_4868 {
  strings:
    $key_4868 = { 1f 1a [2] 2d 38 [2] 2b 0d [2] 05 0d [2] 3a 11 }

  condition:
    any of them
}