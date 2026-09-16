rule TTP_XOR_WriteProcessMemory_0a4c {
  strings:
    $key_0a4c = { 5d 3e [2] 6f 1c [2] 69 29 [2] 47 29 [2] 78 35 }

  condition:
    any of them
}