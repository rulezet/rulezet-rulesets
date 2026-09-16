rule TTP_XOR_WriteProcessMemory_0f14 {
  strings:
    $key_0f14 = { 58 66 [2] 6a 44 [2] 6c 71 [2] 42 71 [2] 7d 6d }

  condition:
    any of them
}