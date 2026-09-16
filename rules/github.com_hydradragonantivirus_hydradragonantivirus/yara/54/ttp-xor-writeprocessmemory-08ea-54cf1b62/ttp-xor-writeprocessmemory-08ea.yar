rule TTP_XOR_WriteProcessMemory_08ea {
  strings:
    $key_08ea = { 5f 98 [2] 6d ba [2] 6b 8f [2] 45 8f [2] 7a 93 }

  condition:
    any of them
}