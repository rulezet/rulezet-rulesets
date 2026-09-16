rule TTP_XOR_WriteProcessMemory_031c {
  strings:
    $key_031c = { 54 6e [2] 66 4c [2] 60 79 [2] 4e 79 [2] 71 65 }

  condition:
    any of them
}