rule TTP_XOR_WriteProcessMemory_f5fd {
  strings:
    $key_f5fd = { a2 8f [2] 90 ad [2] 96 98 [2] b8 98 [2] 87 84 }

  condition:
    any of them
}