rule TTP_XOR_WriteProcessMemory_7ddf {
  strings:
    $key_7ddf = { 2a ad [2] 18 8f [2] 1e ba [2] 30 ba [2] 0f a6 }

  condition:
    any of them
}