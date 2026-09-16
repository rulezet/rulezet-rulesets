rule TTP_XOR_WriteProcessMemory_80ea {
  strings:
    $key_80ea = { d7 98 [2] e5 ba [2] e3 8f [2] cd 8f [2] f2 93 }

  condition:
    any of them
}