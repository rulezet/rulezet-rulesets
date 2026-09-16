rule TTP_XOR_WriteProcessMemory_6c2c {
  strings:
    $key_6c2c = { 3b 5e [2] 09 7c [2] 0f 49 [2] 21 49 [2] 1e 55 }

  condition:
    any of them
}