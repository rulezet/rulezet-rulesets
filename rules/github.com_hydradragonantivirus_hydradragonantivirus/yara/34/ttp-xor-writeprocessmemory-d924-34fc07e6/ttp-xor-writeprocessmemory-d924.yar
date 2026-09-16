rule TTP_XOR_WriteProcessMemory_d924 {
  strings:
    $key_d924 = { 8e 56 [2] bc 74 [2] ba 41 [2] 94 41 [2] ab 5d }

  condition:
    any of them
}