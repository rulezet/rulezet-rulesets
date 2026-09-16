rule TTP_XOR_WriteProcessMemory_66ea {
  strings:
    $key_66ea = { 31 98 [2] 03 ba [2] 05 8f [2] 2b 8f [2] 14 93 }

  condition:
    any of them
}