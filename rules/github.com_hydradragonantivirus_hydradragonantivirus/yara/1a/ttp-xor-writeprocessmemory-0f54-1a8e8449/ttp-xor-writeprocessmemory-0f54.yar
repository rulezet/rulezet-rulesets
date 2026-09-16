rule TTP_XOR_WriteProcessMemory_0f54 {
  strings:
    $key_0f54 = { 58 26 [2] 6a 04 [2] 6c 31 [2] 42 31 [2] 7d 2d }

  condition:
    any of them
}