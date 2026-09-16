rule TTP_XOR_WriteProcessMemory_0d7c {
  strings:
    $key_0d7c = { 5a 0e [2] 68 2c [2] 6e 19 [2] 40 19 [2] 7f 05 }

  condition:
    any of them
}