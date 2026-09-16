rule TTP_XOR_WriteProcessMemory_c841 {
  strings:
    $key_c841 = { 9f 33 [2] ad 11 [2] ab 24 [2] 85 24 [2] ba 38 }

  condition:
    any of them
}