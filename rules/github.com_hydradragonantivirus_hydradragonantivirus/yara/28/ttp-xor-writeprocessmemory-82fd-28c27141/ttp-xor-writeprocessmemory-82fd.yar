rule TTP_XOR_WriteProcessMemory_82fd {
  strings:
    $key_82fd = { d5 8f [2] e7 ad [2] e1 98 [2] cf 98 [2] f0 84 }

  condition:
    any of them
}