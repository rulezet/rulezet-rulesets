rule TTP_XOR_WriteProcessMemory_33ea {
  strings:
    $key_33ea = { 64 98 [2] 56 ba [2] 50 8f [2] 7e 8f [2] 41 93 }

  condition:
    any of them
}