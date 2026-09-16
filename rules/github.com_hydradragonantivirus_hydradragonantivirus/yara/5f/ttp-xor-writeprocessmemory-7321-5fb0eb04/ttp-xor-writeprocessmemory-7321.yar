rule TTP_XOR_WriteProcessMemory_7321 {
  strings:
    $key_7321 = { 24 53 [2] 16 71 [2] 10 44 [2] 3e 44 [2] 01 58 }

  condition:
    any of them
}