rule TTP_XOR_WriteProcessMemory_12ea {
  strings:
    $key_12ea = { 45 98 [2] 77 ba [2] 71 8f [2] 5f 8f [2] 60 93 }

  condition:
    any of them
}