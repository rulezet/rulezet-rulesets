rule TTP_XOR_WriteProcessMemory_c864 {
  strings:
    $key_c864 = { 9f 16 [2] ad 34 [2] ab 01 [2] 85 01 [2] ba 1d }

  condition:
    any of them
}