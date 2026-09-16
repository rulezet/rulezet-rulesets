rule TTP_XOR_WriteProcessMemory_432c {
  strings:
    $key_432c = { 14 5e [2] 26 7c [2] 20 49 [2] 0e 49 [2] 31 55 }

  condition:
    any of them
}