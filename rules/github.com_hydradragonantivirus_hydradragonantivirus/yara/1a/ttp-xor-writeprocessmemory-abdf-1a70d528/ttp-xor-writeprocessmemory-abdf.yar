rule TTP_XOR_WriteProcessMemory_abdf {
  strings:
    $key_abdf = { fc ad [2] ce 8f [2] c8 ba [2] e6 ba [2] d9 a6 }

  condition:
    any of them
}