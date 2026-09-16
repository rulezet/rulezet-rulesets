rule TTP_XOR_WriteProcessMemory_0d2c {
  strings:
    $key_0d2c = { 5a 5e [2] 68 7c [2] 6e 49 [2] 40 49 [2] 7f 55 }

  condition:
    any of them
}