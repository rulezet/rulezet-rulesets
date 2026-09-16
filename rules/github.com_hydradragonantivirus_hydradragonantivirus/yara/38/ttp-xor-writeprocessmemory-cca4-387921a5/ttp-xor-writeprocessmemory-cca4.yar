rule TTP_XOR_WriteProcessMemory_cca4 {
  strings:
    $key_cca4 = { 9b d6 [2] a9 f4 [2] af c1 [2] 81 c1 [2] be dd }

  condition:
    any of them
}