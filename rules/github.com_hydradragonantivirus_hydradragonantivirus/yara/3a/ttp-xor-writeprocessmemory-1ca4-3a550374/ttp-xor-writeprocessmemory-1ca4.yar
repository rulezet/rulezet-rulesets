rule TTP_XOR_WriteProcessMemory_1ca4 {
  strings:
    $key_1ca4 = { 4b d6 [2] 79 f4 [2] 7f c1 [2] 51 c1 [2] 6e dd }

  condition:
    any of them
}