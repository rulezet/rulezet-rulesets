rule TTP_XOR_WriteProcessMemory_6ddf {
  strings:
    $key_6ddf = { 3a ad [2] 08 8f [2] 0e ba [2] 20 ba [2] 1f a6 }

  condition:
    any of them
}