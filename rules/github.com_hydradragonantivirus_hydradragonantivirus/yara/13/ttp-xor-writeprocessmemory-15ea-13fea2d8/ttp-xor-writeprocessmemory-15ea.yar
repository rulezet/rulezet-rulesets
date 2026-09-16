rule TTP_XOR_WriteProcessMemory_15ea {
  strings:
    $key_15ea = { 42 98 [2] 70 ba [2] 76 8f [2] 58 8f [2] 67 93 }

  condition:
    any of them
}