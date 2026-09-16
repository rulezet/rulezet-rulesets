rule TTP_XOR_WriteProcessMemory_0f21 {
  strings:
    $key_0f21 = { 58 53 [2] 6a 71 [2] 6c 44 [2] 42 44 [2] 7d 58 }

  condition:
    any of them
}