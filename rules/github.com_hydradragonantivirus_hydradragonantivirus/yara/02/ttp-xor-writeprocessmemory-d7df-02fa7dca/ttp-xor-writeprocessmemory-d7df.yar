rule TTP_XOR_WriteProcessMemory_d7df {
  strings:
    $key_d7df = { 80 ad [2] b2 8f [2] b4 ba [2] 9a ba [2] a5 a6 }

  condition:
    any of them
}