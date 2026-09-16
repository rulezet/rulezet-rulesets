rule TTP_XOR_WriteProcessMemory_d947 {
  strings:
    $key_d947 = { 8e 35 [2] bc 17 [2] ba 22 [2] 94 22 [2] ab 3e }

  condition:
    any of them
}