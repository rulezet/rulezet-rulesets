rule TTP_XOR_WriteProcessMemory_35ea {
  strings:
    $key_35ea = { 62 98 [2] 50 ba [2] 56 8f [2] 78 8f [2] 47 93 }

  condition:
    any of them
}