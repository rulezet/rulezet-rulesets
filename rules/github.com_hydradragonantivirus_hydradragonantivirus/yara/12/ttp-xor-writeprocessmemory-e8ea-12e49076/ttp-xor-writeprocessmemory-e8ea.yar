rule TTP_XOR_WriteProcessMemory_e8ea {
  strings:
    $key_e8ea = { bf 98 [2] 8d ba [2] 8b 8f [2] a5 8f [2] 9a 93 }

  condition:
    any of them
}