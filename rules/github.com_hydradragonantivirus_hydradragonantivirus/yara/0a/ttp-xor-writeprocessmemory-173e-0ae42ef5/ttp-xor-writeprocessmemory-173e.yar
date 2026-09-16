rule TTP_XOR_WriteProcessMemory_173e {
  strings:
    $key_173e = { 40 4c [2] 72 6e [2] 74 5b [2] 5a 5b [2] 65 47 }

  condition:
    any of them
}