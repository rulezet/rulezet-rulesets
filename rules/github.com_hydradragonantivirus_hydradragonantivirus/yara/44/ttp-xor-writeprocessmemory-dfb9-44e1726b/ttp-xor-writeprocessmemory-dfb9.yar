rule TTP_XOR_WriteProcessMemory_dfb9 {
  strings:
    $key_dfb9 = { 88 cb [2] ba e9 [2] bc dc [2] 92 dc [2] ad c0 }

  condition:
    any of them
}