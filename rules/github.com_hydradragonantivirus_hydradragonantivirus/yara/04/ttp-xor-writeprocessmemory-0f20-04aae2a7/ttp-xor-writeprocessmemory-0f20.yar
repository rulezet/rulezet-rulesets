rule TTP_XOR_WriteProcessMemory_0f20 {
  strings:
    $key_0f20 = { 58 52 [2] 6a 70 [2] 6c 45 [2] 42 45 [2] 7d 59 }

  condition:
    any of them
}