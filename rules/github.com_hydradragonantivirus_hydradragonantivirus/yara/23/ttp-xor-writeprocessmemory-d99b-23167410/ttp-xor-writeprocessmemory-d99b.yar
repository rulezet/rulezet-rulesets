rule TTP_XOR_WriteProcessMemory_d99b {
  strings:
    $key_d99b = { 8e e9 [2] bc cb [2] ba fe [2] 94 fe [2] ab e2 }

  condition:
    any of them
}