rule TTP_XOR_WriteProcessMemory_474c {
  strings:
    $key_474c = { 10 3e [2] 22 1c [2] 24 29 [2] 0a 29 [2] 35 35 }

  condition:
    any of them
}