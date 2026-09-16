rule TTP_XOR_WriteProcessMemory_c82c {
  strings:
    $key_c82c = { 9f 5e [2] ad 7c [2] ab 49 [2] 85 49 [2] ba 55 }

  condition:
    any of them
}