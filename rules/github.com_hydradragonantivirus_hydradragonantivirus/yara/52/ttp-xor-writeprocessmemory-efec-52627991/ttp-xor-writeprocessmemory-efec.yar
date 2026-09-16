rule TTP_XOR_WriteProcessMemory_efec {
  strings:
    $key_efec = { b8 9e [2] 8a bc [2] 8c 89 [2] a2 89 [2] 9d 95 }

  condition:
    any of them
}