rule TTP_XOR_WriteProcessMemory_d4df {
  strings:
    $key_d4df = { 83 ad [2] b1 8f [2] b7 ba [2] 99 ba [2] a6 a6 }

  condition:
    any of them
}