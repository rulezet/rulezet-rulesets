rule TTP_XOR_WriteProcessMemory_c836 {
  strings:
    $key_c836 = { 9f 44 [2] ad 66 [2] ab 53 [2] 85 53 [2] ba 4f }

  condition:
    any of them
}