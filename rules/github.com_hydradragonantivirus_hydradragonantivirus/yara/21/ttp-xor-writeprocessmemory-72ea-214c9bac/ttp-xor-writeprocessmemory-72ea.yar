rule TTP_XOR_WriteProcessMemory_72ea {
  strings:
    $key_72ea = { 25 98 [2] 17 ba [2] 11 8f [2] 3f 8f [2] 00 93 }

  condition:
    any of them
}