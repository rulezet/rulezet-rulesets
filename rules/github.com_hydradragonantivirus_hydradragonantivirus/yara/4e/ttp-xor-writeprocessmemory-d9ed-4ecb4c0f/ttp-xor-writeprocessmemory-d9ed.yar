rule TTP_XOR_WriteProcessMemory_d9ed {
  strings:
    $key_d9ed = { 8e 9f [2] bc bd [2] ba 88 [2] 94 88 [2] ab 94 }

  condition:
    any of them
}