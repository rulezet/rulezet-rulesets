rule TTP_XOR_WriteProcessMemory_25fd {
  strings:
    $key_25fd = { 72 8f [2] 40 ad [2] 46 98 [2] 68 98 [2] 57 84 }

  condition:
    any of them
}