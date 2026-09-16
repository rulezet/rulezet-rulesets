rule TTP_XOR_WriteProcessMemory_7d03 {
  strings:
    $key_7d03 = { 2a 71 [2] 18 53 [2] 1e 66 [2] 30 66 [2] 0f 7a }

  condition:
    any of them
}