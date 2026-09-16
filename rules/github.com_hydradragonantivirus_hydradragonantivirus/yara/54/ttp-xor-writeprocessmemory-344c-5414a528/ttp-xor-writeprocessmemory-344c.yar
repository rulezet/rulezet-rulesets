rule TTP_XOR_WriteProcessMemory_344c {
  strings:
    $key_344c = { 63 3e [2] 51 1c [2] 57 29 [2] 79 29 [2] 46 35 }

  condition:
    any of them
}