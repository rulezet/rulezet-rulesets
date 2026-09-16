rule TTP_XOR_WriteProcessMemory_90fd {
  strings:
    $key_90fd = { c7 8f [2] f5 ad [2] f3 98 [2] dd 98 [2] e2 84 }

  condition:
    any of them
}