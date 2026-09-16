rule TTP_XOR_WriteProcessMemory_2c59 {
  strings:
    $key_2c59 = { 7b 2b [2] 49 09 [2] 4f 3c [2] 61 3c [2] 5e 20 }

  condition:
    any of them
}