rule TTP_XOR_WriteProcessMemory_40fd {
  strings:
    $key_40fd = { 17 8f [2] 25 ad [2] 23 98 [2] 0d 98 [2] 32 84 }

  condition:
    any of them
}