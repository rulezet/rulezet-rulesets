rule TTP_XOR_WriteProcessMemory_360c {
  strings:
    $key_360c = { 61 7e [2] 53 5c [2] 55 69 [2] 7b 69 [2] 44 75 }

  condition:
    any of them
}