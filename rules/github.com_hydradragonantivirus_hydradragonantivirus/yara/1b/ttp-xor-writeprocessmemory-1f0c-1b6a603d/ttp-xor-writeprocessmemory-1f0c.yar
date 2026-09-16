rule TTP_XOR_WriteProcessMemory_1f0c {
  strings:
    $key_1f0c = { 48 7e [2] 7a 5c [2] 7c 69 [2] 52 69 [2] 6d 75 }

  condition:
    any of them
}