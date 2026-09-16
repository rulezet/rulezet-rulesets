rule TTP_XOR_WriteProcessMemory_0ca3 {
  strings:
    $key_0ca3 = { 5b d1 [2] 69 f3 [2] 6f c6 [2] 41 c6 [2] 7e da }

  condition:
    any of them
}