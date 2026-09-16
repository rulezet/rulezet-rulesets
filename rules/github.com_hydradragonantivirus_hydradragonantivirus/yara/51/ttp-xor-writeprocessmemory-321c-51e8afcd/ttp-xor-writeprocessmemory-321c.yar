rule TTP_XOR_WriteProcessMemory_321c {
  strings:
    $key_321c = { 65 6e [2] 57 4c [2] 51 79 [2] 7f 79 [2] 40 65 }

  condition:
    any of them
}