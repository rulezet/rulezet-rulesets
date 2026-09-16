rule TTP_XOR_WriteProcessMemory_09ac {
  strings:
    $key_09ac = { 5e de [2] 6c fc [2] 6a c9 [2] 44 c9 [2] 7b d5 }

  condition:
    any of them
}