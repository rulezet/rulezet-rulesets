rule TTP_XOR_WriteProcessMemory_d9d8 {
  strings:
    $key_d9d8 = { 8e aa [2] bc 88 [2] ba bd [2] 94 bd [2] ab a1 }

  condition:
    any of them
}