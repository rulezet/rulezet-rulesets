rule TTP_XOR_WriteProcessMemory_c7ea {
  strings:
    $key_c7ea = { 90 98 [2] a2 ba [2] a4 8f [2] 8a 8f [2] b5 93 }

  condition:
    any of them
}