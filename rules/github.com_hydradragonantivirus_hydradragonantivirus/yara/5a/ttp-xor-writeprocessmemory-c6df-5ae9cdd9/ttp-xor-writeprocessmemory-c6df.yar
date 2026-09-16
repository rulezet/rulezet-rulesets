rule TTP_XOR_WriteProcessMemory_c6df {
  strings:
    $key_c6df = { 91 ad [2] a3 8f [2] a5 ba [2] 8b ba [2] b4 a6 }

  condition:
    any of them
}