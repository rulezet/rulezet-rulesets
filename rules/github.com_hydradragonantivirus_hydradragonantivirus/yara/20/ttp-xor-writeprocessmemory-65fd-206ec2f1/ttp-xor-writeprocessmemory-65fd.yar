rule TTP_XOR_WriteProcessMemory_65fd {
  strings:
    $key_65fd = { 32 8f [2] 00 ad [2] 06 98 [2] 28 98 [2] 17 84 }

  condition:
    any of them
}