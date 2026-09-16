rule TTP_XOR_WriteProcessMemory_f7ea {
  strings:
    $key_f7ea = { a0 98 [2] 92 ba [2] 94 8f [2] ba 8f [2] 85 93 }

  condition:
    any of them
}