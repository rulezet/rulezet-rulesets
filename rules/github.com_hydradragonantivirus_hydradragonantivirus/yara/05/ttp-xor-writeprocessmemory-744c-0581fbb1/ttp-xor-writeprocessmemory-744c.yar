rule TTP_XOR_WriteProcessMemory_744c {
  strings:
    $key_744c = { 23 3e [2] 11 1c [2] 17 29 [2] 39 29 [2] 06 35 }

  condition:
    any of them
}