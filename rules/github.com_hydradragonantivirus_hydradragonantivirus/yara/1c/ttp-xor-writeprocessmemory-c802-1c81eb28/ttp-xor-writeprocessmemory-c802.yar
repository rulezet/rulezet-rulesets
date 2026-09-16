rule TTP_XOR_WriteProcessMemory_c802 {
  strings:
    $key_c802 = { 9f 70 [2] ad 52 [2] ab 67 [2] 85 67 [2] ba 7b }

  condition:
    any of them
}