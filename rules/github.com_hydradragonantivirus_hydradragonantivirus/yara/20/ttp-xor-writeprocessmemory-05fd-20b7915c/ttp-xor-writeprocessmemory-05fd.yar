rule TTP_XOR_WriteProcessMemory_05fd {
  strings:
    $key_05fd = { 52 8f [2] 60 ad [2] 66 98 [2] 48 98 [2] 77 84 }

  condition:
    any of them
}