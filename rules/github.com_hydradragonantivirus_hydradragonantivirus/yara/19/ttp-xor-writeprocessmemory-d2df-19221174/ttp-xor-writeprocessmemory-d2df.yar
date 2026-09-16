rule TTP_XOR_WriteProcessMemory_d2df {
  strings:
    $key_d2df = { 85 ad [2] b7 8f [2] b1 ba [2] 9f ba [2] a0 a6 }

  condition:
    any of them
}