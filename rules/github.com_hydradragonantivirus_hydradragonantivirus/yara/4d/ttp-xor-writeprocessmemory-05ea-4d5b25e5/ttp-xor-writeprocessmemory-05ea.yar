rule TTP_XOR_WriteProcessMemory_05ea {
  strings:
    $key_05ea = { 52 98 [2] 60 ba [2] 66 8f [2] 48 8f [2] 77 93 }

  condition:
    any of them
}