rule TTP_XOR_WriteProcessMemory_5a21 {
  strings:
    $key_5a21 = { 0d 53 [2] 3f 71 [2] 39 44 [2] 17 44 [2] 28 58 }

  condition:
    any of them
}