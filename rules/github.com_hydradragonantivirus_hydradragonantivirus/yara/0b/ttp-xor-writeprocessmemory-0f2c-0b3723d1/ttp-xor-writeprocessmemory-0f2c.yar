rule TTP_XOR_WriteProcessMemory_0f2c {
  strings:
    $key_0f2c = { 58 5e [2] 6a 7c [2] 6c 49 [2] 42 49 [2] 7d 55 }

  condition:
    any of them
}