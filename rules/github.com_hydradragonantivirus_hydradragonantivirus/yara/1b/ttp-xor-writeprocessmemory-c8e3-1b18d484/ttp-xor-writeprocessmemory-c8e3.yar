rule TTP_XOR_WriteProcessMemory_c8e3 {
  strings:
    $key_c8e3 = { 9f 91 [2] ad b3 [2] ab 86 [2] 85 86 [2] ba 9a }

  condition:
    any of them
}