rule TTP_XOR_WriteProcessMemory_f11f {
  strings:
    $key_f11f = { a6 6d [2] 94 4f [2] 92 7a [2] bc 7a [2] 83 66 }

  condition:
    any of them
}