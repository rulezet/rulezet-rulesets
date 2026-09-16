rule TTP_XOR_WriteProcessMemory_c3ea {
  strings:
    $key_c3ea = { 94 98 [2] a6 ba [2] a0 8f [2] 8e 8f [2] b1 93 }

  condition:
    any of them
}