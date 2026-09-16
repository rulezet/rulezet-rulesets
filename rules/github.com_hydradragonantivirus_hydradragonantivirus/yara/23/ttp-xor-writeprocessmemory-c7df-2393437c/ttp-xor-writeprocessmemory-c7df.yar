rule TTP_XOR_WriteProcessMemory_c7df {
  strings:
    $key_c7df = { 90 ad [2] a2 8f [2] a4 ba [2] 8a ba [2] b5 a6 }

  condition:
    any of them
}