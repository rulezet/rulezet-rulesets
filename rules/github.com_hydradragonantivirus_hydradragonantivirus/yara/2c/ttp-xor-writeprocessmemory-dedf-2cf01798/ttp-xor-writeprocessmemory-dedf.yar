rule TTP_XOR_WriteProcessMemory_dedf {
  strings:
    $key_dedf = { 89 ad [2] bb 8f [2] bd ba [2] 93 ba [2] ac a6 }

  condition:
    any of them
}