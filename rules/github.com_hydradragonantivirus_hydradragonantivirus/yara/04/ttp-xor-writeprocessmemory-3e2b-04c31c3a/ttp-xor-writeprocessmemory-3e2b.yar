rule TTP_XOR_WriteProcessMemory_3e2b {
  strings:
    $key_3e2b = { 69 59 [2] 5b 7b [2] 5d 4e [2] 73 4e [2] 4c 52 }

  condition:
    any of them
}