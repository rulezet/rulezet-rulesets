rule TTP_XOR_WriteProcessMemory_36ea {
  strings:
    $key_36ea = { 61 98 [2] 53 ba [2] 55 8f [2] 7b 8f [2] 44 93 }

  condition:
    any of them
}