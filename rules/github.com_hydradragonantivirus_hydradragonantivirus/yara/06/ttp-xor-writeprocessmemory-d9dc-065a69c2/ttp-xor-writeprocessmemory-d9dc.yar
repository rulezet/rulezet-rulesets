rule TTP_XOR_WriteProcessMemory_d9dc {
  strings:
    $key_d9dc = { 8e ae [2] bc 8c [2] ba b9 [2] 94 b9 [2] ab a5 }

  condition:
    any of them
}