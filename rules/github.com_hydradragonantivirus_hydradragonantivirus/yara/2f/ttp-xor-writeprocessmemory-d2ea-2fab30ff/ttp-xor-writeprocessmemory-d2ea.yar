rule TTP_XOR_WriteProcessMemory_d2ea {
  strings:
    $key_d2ea = { 85 98 [2] b7 ba [2] b1 8f [2] 9f 8f [2] a0 93 }

  condition:
    any of them
}