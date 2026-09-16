rule TTP_XOR_WriteProcessMemory_92ea {
  strings:
    $key_92ea = { c5 98 [2] f7 ba [2] f1 8f [2] df 8f [2] e0 93 }

  condition:
    any of them
}