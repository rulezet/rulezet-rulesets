rule TTP_XOR_WriteProcessMemory_f1ec {
  strings:
    $key_f1ec = { a6 9e [2] 94 bc [2] 92 89 [2] bc 89 [2] 83 95 }

  condition:
    any of them
}