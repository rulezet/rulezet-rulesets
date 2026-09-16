rule TTP_XOR_WriteProcessMemory_23df {
  strings:
    $key_23df = { 74 ad [2] 46 8f [2] 40 ba [2] 6e ba [2] 51 a6 }

  condition:
    any of them
}