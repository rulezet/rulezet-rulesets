rule TTP_XOR_WriteProcessMemory_7903 {
  strings:
    $key_7903 = { 2e 71 [2] 1c 53 [2] 1a 66 [2] 34 66 [2] 0b 7a }

  condition:
    any of them
}