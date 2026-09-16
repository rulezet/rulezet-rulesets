rule TTP_XOR_WriteProcessMemory_ef7c {
  strings:
    $key_ef7c = { b8 0e [2] 8a 2c [2] 8c 19 [2] a2 19 [2] 9d 05 }

  condition:
    any of them
}