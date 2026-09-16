rule TTP_XOR_WriteProcessMemory_18cd {
  strings:
    $key_18cd = { 4f bf [2] 7d 9d [2] 7b a8 [2] 55 a8 [2] 6a b4 }

  condition:
    any of them
}