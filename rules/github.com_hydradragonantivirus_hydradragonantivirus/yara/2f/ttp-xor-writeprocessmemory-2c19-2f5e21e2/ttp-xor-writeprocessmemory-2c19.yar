rule TTP_XOR_WriteProcessMemory_2c19 {
  strings:
    $key_2c19 = { 7b 6b [2] 49 49 [2] 4f 7c [2] 61 7c [2] 5e 60 }

  condition:
    any of them
}