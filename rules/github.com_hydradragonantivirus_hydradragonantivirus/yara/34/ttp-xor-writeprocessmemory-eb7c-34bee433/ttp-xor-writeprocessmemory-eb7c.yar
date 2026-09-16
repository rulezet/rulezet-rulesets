rule TTP_XOR_WriteProcessMemory_eb7c {
  strings:
    $key_eb7c = { bc 0e [2] 8e 2c [2] 88 19 [2] a6 19 [2] 99 05 }

  condition:
    any of them
}