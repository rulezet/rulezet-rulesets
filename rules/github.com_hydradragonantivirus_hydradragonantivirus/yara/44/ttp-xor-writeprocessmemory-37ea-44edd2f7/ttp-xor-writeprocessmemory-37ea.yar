rule TTP_XOR_WriteProcessMemory_37ea {
  strings:
    $key_37ea = { 60 98 [2] 52 ba [2] 54 8f [2] 7a 8f [2] 45 93 }

  condition:
    any of them
}