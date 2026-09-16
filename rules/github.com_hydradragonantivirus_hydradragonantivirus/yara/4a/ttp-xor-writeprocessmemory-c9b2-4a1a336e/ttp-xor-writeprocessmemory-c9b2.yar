rule TTP_XOR_WriteProcessMemory_c9b2 {
  strings:
    $key_c9b2 = { 9e c0 [2] ac e2 [2] aa d7 [2] 84 d7 [2] bb cb }

  condition:
    any of them
}