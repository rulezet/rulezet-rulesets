rule TTP_XOR_WriteProcessMemory_780a {
  strings:
    $key_780a = { 2f 78 [2] 1d 5a [2] 1b 6f [2] 35 6f [2] 0a 73 }

  condition:
    any of them
}