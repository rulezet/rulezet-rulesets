rule TTP_XOR_WriteProcessMemory_2c7c {
  strings:
    $key_2c7c = { 7b 0e [2] 49 2c [2] 4f 19 [2] 61 19 [2] 5e 05 }

  condition:
    any of them
}