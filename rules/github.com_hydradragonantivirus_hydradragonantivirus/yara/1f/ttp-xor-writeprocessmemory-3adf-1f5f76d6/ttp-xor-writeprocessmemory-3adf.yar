rule TTP_XOR_WriteProcessMemory_3adf {
  strings:
    $key_3adf = { 6d ad [2] 5f 8f [2] 59 ba [2] 77 ba [2] 48 a6 }

  condition:
    any of them
}