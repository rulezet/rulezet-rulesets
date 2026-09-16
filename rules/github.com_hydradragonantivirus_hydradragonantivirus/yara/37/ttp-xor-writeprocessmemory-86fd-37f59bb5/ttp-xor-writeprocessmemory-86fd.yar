rule TTP_XOR_WriteProcessMemory_86fd {
  strings:
    $key_86fd = { d1 8f [2] e3 ad [2] e5 98 [2] cb 98 [2] f4 84 }

  condition:
    any of them
}