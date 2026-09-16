rule TTP_XOR_WriteProcessMemory_0021 {
  strings:
    $key_0021 = { 57 53 [2] 65 71 [2] 63 44 [2] 4d 44 [2] 72 58 }

  condition:
    any of them
}