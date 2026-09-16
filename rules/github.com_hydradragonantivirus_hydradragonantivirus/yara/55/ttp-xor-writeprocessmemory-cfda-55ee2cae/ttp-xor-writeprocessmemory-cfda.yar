rule TTP_XOR_WriteProcessMemory_cfda {
  strings:
    $key_cfda = { 98 a8 [2] aa 8a [2] ac bf [2] 82 bf [2] bd a3 }

  condition:
    any of them
}