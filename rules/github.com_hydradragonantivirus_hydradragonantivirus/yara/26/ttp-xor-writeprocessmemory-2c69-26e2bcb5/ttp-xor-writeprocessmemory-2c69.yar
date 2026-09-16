rule TTP_XOR_WriteProcessMemory_2c69 {
  strings:
    $key_2c69 = { 7b 1b [2] 49 39 [2] 4f 0c [2] 61 0c [2] 5e 10 }

  condition:
    any of them
}