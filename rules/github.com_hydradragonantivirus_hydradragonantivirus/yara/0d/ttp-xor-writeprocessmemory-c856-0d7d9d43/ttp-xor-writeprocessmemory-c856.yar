rule TTP_XOR_WriteProcessMemory_c856 {
  strings:
    $key_c856 = { 9f 24 [2] ad 06 [2] ab 33 [2] 85 33 [2] ba 2f }

  condition:
    any of them
}