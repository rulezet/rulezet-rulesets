rule TTP_XOR_WriteProcessMemory_f12a {
  strings:
    $key_f12a = { a6 58 [2] 94 7a [2] 92 4f [2] bc 4f [2] 83 53 }

  condition:
    any of them
}