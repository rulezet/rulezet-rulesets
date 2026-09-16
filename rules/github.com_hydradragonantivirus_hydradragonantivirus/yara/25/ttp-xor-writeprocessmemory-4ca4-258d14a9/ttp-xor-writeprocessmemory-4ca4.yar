rule TTP_XOR_WriteProcessMemory_4ca4 {
  strings:
    $key_4ca4 = { 1b d6 [2] 29 f4 [2] 2f c1 [2] 01 c1 [2] 3e dd }

  condition:
    any of them
}