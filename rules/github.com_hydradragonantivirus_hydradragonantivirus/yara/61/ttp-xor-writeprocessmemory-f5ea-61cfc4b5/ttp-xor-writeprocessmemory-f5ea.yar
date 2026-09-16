rule TTP_XOR_WriteProcessMemory_f5ea {
  strings:
    $key_f5ea = { a2 98 [2] 90 ba [2] 96 8f [2] b8 8f [2] 87 93 }

  condition:
    any of them
}