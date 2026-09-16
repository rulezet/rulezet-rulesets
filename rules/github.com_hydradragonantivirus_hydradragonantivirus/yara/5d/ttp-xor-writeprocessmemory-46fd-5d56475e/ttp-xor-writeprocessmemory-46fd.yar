rule TTP_XOR_WriteProcessMemory_46fd {
  strings:
    $key_46fd = { 11 8f [2] 23 ad [2] 25 98 [2] 0b 98 [2] 34 84 }

  condition:
    any of them
}