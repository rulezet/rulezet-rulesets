rule TTP_XOR_WriteProcessMemory_cfcd {
  strings:
    $key_cfcd = { 98 bf [2] aa 9d [2] ac a8 [2] 82 a8 [2] bd b4 }

  condition:
    any of them
}