rule TTP_XOR_WriteProcessMemory_10ea {
  strings:
    $key_10ea = { 47 98 [2] 75 ba [2] 73 8f [2] 5d 8f [2] 62 93 }

  condition:
    any of them
}