rule TTP_XOR_WriteProcessMemory_e9ea {
  strings:
    $key_e9ea = { be 98 [2] 8c ba [2] 8a 8f [2] a4 8f [2] 9b 93 }

  condition:
    any of them
}