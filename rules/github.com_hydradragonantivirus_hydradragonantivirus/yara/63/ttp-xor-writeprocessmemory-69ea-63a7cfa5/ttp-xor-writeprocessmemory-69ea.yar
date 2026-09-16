rule TTP_XOR_WriteProcessMemory_69ea {
  strings:
    $key_69ea = { 3e 98 [2] 0c ba [2] 0a 8f [2] 24 8f [2] 1b 93 }

  condition:
    any of them
}