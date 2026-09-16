rule TTP_XOR_WriteProcessMemory_173c {
  strings:
    $key_173c = { 40 4e [2] 72 6c [2] 74 59 [2] 5a 59 [2] 65 45 }

  condition:
    any of them
}