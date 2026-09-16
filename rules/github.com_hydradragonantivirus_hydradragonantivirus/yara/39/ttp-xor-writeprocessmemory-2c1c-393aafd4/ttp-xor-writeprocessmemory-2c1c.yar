rule TTP_XOR_WriteProcessMemory_2c1c {
  strings:
    $key_2c1c = { 7b 6e [2] 49 4c [2] 4f 79 [2] 61 79 [2] 5e 65 }

  condition:
    any of them
}