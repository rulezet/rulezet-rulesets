rule TTP_XOR_WriteProcessMemory_c8ee {
  strings:
    $key_c8ee = { 9f 9c [2] ad be [2] ab 8b [2] 85 8b [2] ba 97 }

  condition:
    any of them
}