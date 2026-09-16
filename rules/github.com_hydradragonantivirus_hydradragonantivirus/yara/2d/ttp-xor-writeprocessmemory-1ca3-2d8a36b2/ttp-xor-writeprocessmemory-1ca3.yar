rule TTP_XOR_WriteProcessMemory_1ca3 {
  strings:
    $key_1ca3 = { 4b d1 [2] 79 f3 [2] 7f c6 [2] 51 c6 [2] 6e da }

  condition:
    any of them
}