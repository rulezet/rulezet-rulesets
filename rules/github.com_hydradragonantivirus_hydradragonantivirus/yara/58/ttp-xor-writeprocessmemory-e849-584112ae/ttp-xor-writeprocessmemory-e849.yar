rule TTP_XOR_WriteProcessMemory_e849 {
  strings:
    $key_e849 = { bf 3b [2] 8d 19 [2] 8b 2c [2] a5 2c [2] 9a 30 }

  condition:
    any of them
}