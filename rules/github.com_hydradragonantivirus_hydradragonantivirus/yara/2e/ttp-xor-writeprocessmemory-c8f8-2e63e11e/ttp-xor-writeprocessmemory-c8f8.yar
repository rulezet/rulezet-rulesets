rule TTP_XOR_WriteProcessMemory_c8f8 {
  strings:
    $key_c8f8 = { 9f 8a [2] ad a8 [2] ab 9d [2] 85 9d [2] ba 81 }

  condition:
    any of them
}