rule TTP_XOR_WriteProcessMemory_bbdf {
  strings:
    $key_bbdf = { ec ad [2] de 8f [2] d8 ba [2] f6 ba [2] c9 a6 }

  condition:
    any of them
}