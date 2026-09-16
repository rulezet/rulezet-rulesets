rule TTP_XOR_WriteProcessMemory_13ea {
  strings:
    $key_13ea = { 44 98 [2] 76 ba [2] 70 8f [2] 5e 8f [2] 61 93 }

  condition:
    any of them
}