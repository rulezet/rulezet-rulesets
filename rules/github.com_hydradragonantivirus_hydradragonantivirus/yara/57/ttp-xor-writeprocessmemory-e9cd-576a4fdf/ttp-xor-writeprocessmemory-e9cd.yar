rule TTP_XOR_WriteProcessMemory_e9cd {
  strings:
    $key_e9cd = { be bf [2] 8c 9d [2] 8a a8 [2] a4 a8 [2] 9b b4 }

  condition:
    any of them
}