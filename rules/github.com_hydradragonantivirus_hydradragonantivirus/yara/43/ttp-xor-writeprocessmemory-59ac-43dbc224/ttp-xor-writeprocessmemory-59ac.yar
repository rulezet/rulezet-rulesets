rule TTP_XOR_WriteProcessMemory_59ac {
  strings:
    $key_59ac = { 0e de [2] 3c fc [2] 3a c9 [2] 14 c9 [2] 2b d5 }

  condition:
    any of them
}