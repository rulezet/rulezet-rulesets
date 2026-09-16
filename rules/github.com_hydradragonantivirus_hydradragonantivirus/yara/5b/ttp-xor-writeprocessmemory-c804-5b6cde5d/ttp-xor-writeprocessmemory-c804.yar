rule TTP_XOR_WriteProcessMemory_c804 {
  strings:
    $key_c804 = { 9f 76 [2] ad 54 [2] ab 61 [2] 85 61 [2] ba 7d }

  condition:
    any of them
}