rule TTP_XOR_WriteProcessMemory_f1ca {
  strings:
    $key_f1ca = { a6 b8 [2] 94 9a [2] 92 af [2] bc af [2] 83 b3 }

  condition:
    any of them
}