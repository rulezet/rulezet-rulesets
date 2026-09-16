rule TTP_XOR_WriteProcessMemory_d3df {
  strings:
    $key_d3df = { 84 ad [2] b6 8f [2] b0 ba [2] 9e ba [2] a1 a6 }

  condition:
    any of them
}