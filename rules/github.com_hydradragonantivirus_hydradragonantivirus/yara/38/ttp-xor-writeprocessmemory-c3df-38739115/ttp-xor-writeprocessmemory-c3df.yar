rule TTP_XOR_WriteProcessMemory_c3df {
  strings:
    $key_c3df = { 94 ad [2] a6 8f [2] a0 ba [2] 8e ba [2] b1 a6 }

  condition:
    any of them
}