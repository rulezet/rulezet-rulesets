rule TTP_XOR_WriteProcessMemory_0f7c {
  strings:
    $key_0f7c = { 58 0e [2] 6a 2c [2] 6c 19 [2] 42 19 [2] 7d 05 }

  condition:
    any of them
}