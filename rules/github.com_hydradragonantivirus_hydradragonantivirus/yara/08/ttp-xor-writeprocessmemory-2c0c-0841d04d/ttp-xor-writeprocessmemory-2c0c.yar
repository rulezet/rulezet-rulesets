rule TTP_XOR_WriteProcessMemory_2c0c {
  strings:
    $key_2c0c = { 7b 7e [2] 49 5c [2] 4f 69 [2] 61 69 [2] 5e 75 }

  condition:
    any of them
}