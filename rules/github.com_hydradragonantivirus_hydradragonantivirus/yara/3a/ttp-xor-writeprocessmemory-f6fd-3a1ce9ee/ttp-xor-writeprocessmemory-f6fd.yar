rule TTP_XOR_WriteProcessMemory_f6fd {
  strings:
    $key_f6fd = { a1 8f [2] 93 ad [2] 95 98 [2] bb 98 [2] 84 84 }

  condition:
    any of them
}