rule TTP_XOR_WriteProcessMemory_07ea {
  strings:
    $key_07ea = { 50 98 [2] 62 ba [2] 64 8f [2] 4a 8f [2] 75 93 }

  condition:
    any of them
}