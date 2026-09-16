rule TTP_XOR_WriteProcessMemory_c5df {
  strings:
    $key_c5df = { 92 ad [2] a0 8f [2] a6 ba [2] 88 ba [2] b7 a6 }

  condition:
    any of them
}