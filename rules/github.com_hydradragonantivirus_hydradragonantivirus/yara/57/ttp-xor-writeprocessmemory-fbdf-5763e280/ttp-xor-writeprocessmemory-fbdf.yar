rule TTP_XOR_WriteProcessMemory_fbdf {
  strings:
    $key_fbdf = { ac ad [2] 9e 8f [2] 98 ba [2] b6 ba [2] 89 a6 }

  condition:
    any of them
}