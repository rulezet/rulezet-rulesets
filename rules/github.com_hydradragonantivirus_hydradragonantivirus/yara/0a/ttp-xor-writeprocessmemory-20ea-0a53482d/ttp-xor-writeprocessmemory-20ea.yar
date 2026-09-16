rule TTP_XOR_WriteProcessMemory_20ea {
  strings:
    $key_20ea = { 77 98 [2] 45 ba [2] 43 8f [2] 6d 8f [2] 52 93 }

  condition:
    any of them
}