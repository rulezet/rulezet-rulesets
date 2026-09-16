rule TTP_XOR_WriteProcessMemory_51ea {
  strings:
    $key_51ea = { 06 98 [2] 34 ba [2] 32 8f [2] 1c 8f [2] 23 93 }

  condition:
    any of them
}