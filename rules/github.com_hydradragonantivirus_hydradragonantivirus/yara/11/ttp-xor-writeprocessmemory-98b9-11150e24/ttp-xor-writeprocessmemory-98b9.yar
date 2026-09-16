rule TTP_XOR_WriteProcessMemory_98b9 {
  strings:
    $key_98b9 = { cf cb [2] fd e9 [2] fb dc [2] d5 dc [2] ea c0 }

  condition:
    any of them
}