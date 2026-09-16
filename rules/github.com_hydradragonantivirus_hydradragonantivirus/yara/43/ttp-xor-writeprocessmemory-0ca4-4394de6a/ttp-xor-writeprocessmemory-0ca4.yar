rule TTP_XOR_WriteProcessMemory_0ca4 {
  strings:
    $key_0ca4 = { 5b d6 [2] 69 f4 [2] 6f c1 [2] 41 c1 [2] 7e dd }

  condition:
    any of them
}