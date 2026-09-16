rule TTP_XOR_WriteProcessMemory_d969 {
  strings:
    $key_d969 = { 8e 1b [2] bc 39 [2] ba 0c [2] 94 0c [2] ab 10 }

  condition:
    any of them
}