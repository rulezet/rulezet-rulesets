rule TTP_XOR_WriteProcessMemory_41ea {
  strings:
    $key_41ea = { 16 98 [2] 24 ba [2] 22 8f [2] 0c 8f [2] 33 93 }

  condition:
    any of them
}