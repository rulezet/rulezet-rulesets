rule TTP_XOR_WriteProcessMemory_2ca4 {
  strings:
    $key_2ca4 = { 7b d6 [2] 49 f4 [2] 4f c1 [2] 61 c1 [2] 5e dd }

  condition:
    any of them
}