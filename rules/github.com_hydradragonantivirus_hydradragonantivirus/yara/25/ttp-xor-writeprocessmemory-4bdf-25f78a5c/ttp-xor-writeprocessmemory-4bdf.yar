rule TTP_XOR_WriteProcessMemory_4bdf {
  strings:
    $key_4bdf = { 1c ad [2] 2e 8f [2] 28 ba [2] 06 ba [2] 39 a6 }

  condition:
    any of them
}