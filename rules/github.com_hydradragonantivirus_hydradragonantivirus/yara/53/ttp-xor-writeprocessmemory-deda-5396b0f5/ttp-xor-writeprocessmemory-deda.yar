rule TTP_XOR_WriteProcessMemory_deda {
  strings:
    $key_deda = { 89 a8 [2] bb 8a [2] bd bf [2] 93 bf [2] ac a3 }

  condition:
    any of them
}