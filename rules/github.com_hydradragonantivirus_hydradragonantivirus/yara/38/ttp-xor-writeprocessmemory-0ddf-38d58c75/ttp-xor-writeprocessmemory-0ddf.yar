rule TTP_XOR_WriteProcessMemory_0ddf {
  strings:
    $key_0ddf = { 5a ad [2] 68 8f [2] 6e ba [2] 40 ba [2] 7f a6 }

  condition:
    any of them
}