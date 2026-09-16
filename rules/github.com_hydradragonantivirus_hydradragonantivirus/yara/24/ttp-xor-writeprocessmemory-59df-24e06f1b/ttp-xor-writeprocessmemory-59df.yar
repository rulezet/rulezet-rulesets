rule TTP_XOR_WriteProcessMemory_59df {
  strings:
    $key_59df = { 0e ad [2] 3c 8f [2] 3a ba [2] 14 ba [2] 2b a6 }

  condition:
    any of them
}