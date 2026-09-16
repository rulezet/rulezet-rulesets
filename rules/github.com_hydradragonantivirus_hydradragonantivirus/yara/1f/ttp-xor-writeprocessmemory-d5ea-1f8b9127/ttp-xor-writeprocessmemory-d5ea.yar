rule TTP_XOR_WriteProcessMemory_d5ea {
  strings:
    $key_d5ea = { 82 98 [2] b0 ba [2] b6 8f [2] 98 8f [2] a7 93 }

  condition:
    any of them
}