rule TTP_XOR_WriteProcessMemory_46ea {
  strings:
    $key_46ea = { 11 98 [2] 23 ba [2] 25 8f [2] 0b 8f [2] 34 93 }

  condition:
    any of them
}