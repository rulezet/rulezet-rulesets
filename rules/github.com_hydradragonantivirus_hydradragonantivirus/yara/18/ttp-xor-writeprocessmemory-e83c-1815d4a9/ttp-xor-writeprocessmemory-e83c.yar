rule TTP_XOR_WriteProcessMemory_e83c {
  strings:
    $key_e83c = { bf 4e [2] 8d 6c [2] 8b 59 [2] a5 59 [2] 9a 45 }

  condition:
    any of them
}