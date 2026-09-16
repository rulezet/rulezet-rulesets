rule TTP_XOR_WriteProcessMemory_fa2c {
  strings:
    $key_fa2c = { ad 5e [2] 9f 7c [2] 99 49 [2] b7 49 [2] 88 55 }

  condition:
    any of them
}