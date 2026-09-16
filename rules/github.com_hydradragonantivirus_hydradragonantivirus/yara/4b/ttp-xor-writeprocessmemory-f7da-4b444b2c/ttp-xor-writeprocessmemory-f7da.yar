rule TTP_XOR_WriteProcessMemory_f7da {
  strings:
    $key_f7da = { a0 a8 [2] 92 8a [2] 94 bf [2] ba bf [2] 85 a3 }

  condition:
    any of them
}