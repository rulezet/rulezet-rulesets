rule TTP_XOR_WriteProcessMemory_eadf {
  strings:
    $key_eadf = { bd ad [2] 8f 8f [2] 89 ba [2] a7 ba [2] 98 a6 }

  condition:
    any of them
}