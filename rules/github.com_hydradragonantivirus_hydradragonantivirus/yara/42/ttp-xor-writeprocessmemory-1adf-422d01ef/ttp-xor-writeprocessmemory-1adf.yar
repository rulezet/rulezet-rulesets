rule TTP_XOR_WriteProcessMemory_1adf {
  strings:
    $key_1adf = { 4d ad [2] 7f 8f [2] 79 ba [2] 57 ba [2] 68 a6 }

  condition:
    any of them
}