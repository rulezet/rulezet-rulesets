rule TTP_XOR_WriteProcessMemory_f9ac {
  strings:
    $key_f9ac = { ae de [2] 9c fc [2] 9a c9 [2] b4 c9 [2] 8b d5 }

  condition:
    any of them
}