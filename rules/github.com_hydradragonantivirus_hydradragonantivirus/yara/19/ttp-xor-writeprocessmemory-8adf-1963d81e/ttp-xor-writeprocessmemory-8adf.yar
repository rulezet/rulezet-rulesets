rule TTP_XOR_WriteProcessMemory_8adf {
  strings:
    $key_8adf = { dd ad [2] ef 8f [2] e9 ba [2] c7 ba [2] f8 a6 }

  condition:
    any of them
}