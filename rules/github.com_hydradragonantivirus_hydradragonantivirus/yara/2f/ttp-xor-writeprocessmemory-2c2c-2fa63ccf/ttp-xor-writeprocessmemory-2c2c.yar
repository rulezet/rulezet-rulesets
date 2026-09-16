rule TTP_XOR_WriteProcessMemory_2c2c {
  strings:
    $key_2c2c = { 7b 5e [2] 49 7c [2] 4f 49 [2] 61 49 [2] 5e 55 }

  condition:
    any of them
}