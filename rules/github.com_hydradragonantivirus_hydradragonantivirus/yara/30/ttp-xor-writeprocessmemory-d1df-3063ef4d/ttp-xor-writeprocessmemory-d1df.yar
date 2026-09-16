rule TTP_XOR_WriteProcessMemory_d1df {
  strings:
    $key_d1df = { 86 ad [2] b4 8f [2] b2 ba [2] 9c ba [2] a3 a6 }

  condition:
    any of them
}