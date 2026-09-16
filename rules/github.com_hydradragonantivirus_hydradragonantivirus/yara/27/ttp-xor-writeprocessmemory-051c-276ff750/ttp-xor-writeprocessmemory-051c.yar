rule TTP_XOR_WriteProcessMemory_051c {
  strings:
    $key_051c = { 52 6e [2] 60 4c [2] 66 79 [2] 48 79 [2] 77 65 }

  condition:
    any of them
}