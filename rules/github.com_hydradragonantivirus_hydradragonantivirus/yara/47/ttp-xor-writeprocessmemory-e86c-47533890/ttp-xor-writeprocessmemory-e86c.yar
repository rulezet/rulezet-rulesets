rule TTP_XOR_WriteProcessMemory_e86c {
  strings:
    $key_e86c = { bf 1e [2] 8d 3c [2] 8b 09 [2] a5 09 [2] 9a 15 }

  condition:
    any of them
}