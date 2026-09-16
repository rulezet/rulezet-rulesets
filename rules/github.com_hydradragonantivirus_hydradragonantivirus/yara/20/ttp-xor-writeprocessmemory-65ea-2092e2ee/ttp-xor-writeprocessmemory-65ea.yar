rule TTP_XOR_WriteProcessMemory_65ea {
  strings:
    $key_65ea = { 32 98 [2] 00 ba [2] 06 8f [2] 28 8f [2] 17 93 }

  condition:
    any of them
}