rule TTP_XOR_WriteProcessMemory_7adf {
  strings:
    $key_7adf = { 2d ad [2] 1f 8f [2] 19 ba [2] 37 ba [2] 08 a6 }

  condition:
    any of them
}