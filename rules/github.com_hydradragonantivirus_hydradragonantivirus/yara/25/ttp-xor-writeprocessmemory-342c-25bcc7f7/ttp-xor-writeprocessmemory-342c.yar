rule TTP_XOR_WriteProcessMemory_342c {
  strings:
    $key_342c = { 63 5e [2] 51 7c [2] 57 49 [2] 79 49 [2] 46 55 }

  condition:
    any of them
}