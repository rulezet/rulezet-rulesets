rule TTP_XOR_WriteProcessMemory_efdf {
  strings:
    $key_efdf = { b8 ad [2] 8a 8f [2] 8c ba [2] a2 ba [2] 9d a6 }

  condition:
    any of them
}