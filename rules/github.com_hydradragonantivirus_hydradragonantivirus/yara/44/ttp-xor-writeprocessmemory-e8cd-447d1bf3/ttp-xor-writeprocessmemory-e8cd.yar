rule TTP_XOR_WriteProcessMemory_e8cd {
  strings:
    $key_e8cd = { bf bf [2] 8d 9d [2] 8b a8 [2] a5 a8 [2] 9a b4 }

  condition:
    any of them
}