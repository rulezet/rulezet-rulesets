rule TTP_XOR_WriteProcessMemory_eb2c {
  strings:
    $key_eb2c = { bc 5e [2] 8e 7c [2] 88 49 [2] a6 49 [2] 99 55 }

  condition:
    any of them
}