rule TTP_XOR_WriteProcessMemory_c8e8 {
  strings:
    $key_c8e8 = { 9f 9a [2] ad b8 [2] ab 8d [2] 85 8d [2] ba 91 }

  condition:
    any of them
}