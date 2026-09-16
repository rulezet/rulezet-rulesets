rule TTP_XOR_WriteProcessMemory_e5ea {
  strings:
    $key_e5ea = { b2 98 [2] 80 ba [2] 86 8f [2] a8 8f [2] 97 93 }

  condition:
    any of them
}