rule TTP_XOR_WriteProcessMemory_ccdf {
  strings:
    $key_ccdf = { 9b ad [2] a9 8f [2] af ba [2] 81 ba [2] be a6 }

  condition:
    any of them
}