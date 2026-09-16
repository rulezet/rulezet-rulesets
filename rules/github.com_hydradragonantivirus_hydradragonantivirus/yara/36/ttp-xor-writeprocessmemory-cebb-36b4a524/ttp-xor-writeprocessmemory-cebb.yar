rule TTP_XOR_WriteProcessMemory_cebb {
  strings:
    $key_cebb = { 99 c9 [2] ab eb [2] ad de [2] 83 de [2] bc c2 }

  condition:
    any of them
}