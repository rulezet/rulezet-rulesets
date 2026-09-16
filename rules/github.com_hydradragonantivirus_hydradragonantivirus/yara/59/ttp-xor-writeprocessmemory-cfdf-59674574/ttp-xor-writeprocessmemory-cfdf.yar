rule TTP_XOR_WriteProcessMemory_cfdf {
  strings:
    $key_cfdf = { 98 ad [2] aa 8f [2] ac ba [2] 82 ba [2] bd a6 }

  condition:
    any of them
}