rule TTP_XOR_WriteProcessMemory_c831 {
  strings:
    $key_c831 = { 9f 43 [2] ad 61 [2] ab 54 [2] 85 54 [2] ba 48 }

  condition:
    any of them
}