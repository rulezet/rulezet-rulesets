rule TTP_XOR_WriteProcessMemory_176c {
  strings:
    $key_176c = { 40 1e [2] 72 3c [2] 74 09 [2] 5a 09 [2] 65 15 }

  condition:
    any of them
}