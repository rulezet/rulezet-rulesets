rule TTP_XOR_WriteProcessMemory_18ea {
  strings:
    $key_18ea = { 4f 98 [2] 7d ba [2] 7b 8f [2] 55 8f [2] 6a 93 }

  condition:
    any of them
}