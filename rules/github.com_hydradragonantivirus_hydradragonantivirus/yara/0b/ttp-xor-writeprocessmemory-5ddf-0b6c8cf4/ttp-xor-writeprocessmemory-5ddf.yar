rule TTP_XOR_WriteProcessMemory_5ddf {
  strings:
    $key_5ddf = { 0a ad [2] 38 8f [2] 3e ba [2] 10 ba [2] 2f a6 }

  condition:
    any of them
}