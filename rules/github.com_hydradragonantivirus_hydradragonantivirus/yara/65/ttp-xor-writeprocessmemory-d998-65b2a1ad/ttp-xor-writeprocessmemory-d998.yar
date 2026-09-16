rule TTP_XOR_WriteProcessMemory_d998 {
  strings:
    $key_d998 = { 8e ea [2] bc c8 [2] ba fd [2] 94 fd [2] ab e1 }

  condition:
    any of them
}