rule TTP_XOR_WriteProcessMemory_c833 {
  strings:
    $key_c833 = { 9f 41 [2] ad 63 [2] ab 56 [2] 85 56 [2] ba 4a }

  condition:
    any of them
}