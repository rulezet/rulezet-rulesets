rule TTP_XOR_WriteProcessMemory_c2df {
  strings:
    $key_c2df = { 95 ad [2] a7 8f [2] a1 ba [2] 8f ba [2] b0 a6 }

  condition:
    any of them
}