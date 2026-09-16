rule TTP_XOR_WriteProcessMemory_37fd {
  strings:
    $key_37fd = { 60 8f [2] 52 ad [2] 54 98 [2] 7a 98 [2] 45 84 }

  condition:
    any of them
}