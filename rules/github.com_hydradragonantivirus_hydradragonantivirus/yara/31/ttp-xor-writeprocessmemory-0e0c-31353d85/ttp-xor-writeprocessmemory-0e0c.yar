rule TTP_XOR_WriteProcessMemory_0e0c {
  strings:
    $key_0e0c = { 59 7e [2] 6b 5c [2] 6d 69 [2] 43 69 [2] 7c 75 }

  condition:
    any of them
}