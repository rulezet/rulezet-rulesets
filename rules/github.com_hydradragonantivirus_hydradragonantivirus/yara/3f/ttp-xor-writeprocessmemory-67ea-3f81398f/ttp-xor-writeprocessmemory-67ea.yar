rule TTP_XOR_WriteProcessMemory_67ea {
  strings:
    $key_67ea = { 30 98 [2] 02 ba [2] 04 8f [2] 2a 8f [2] 15 93 }

  condition:
    any of them
}