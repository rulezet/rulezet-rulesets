rule TTP_XOR_WriteProcessMemory_5a0c {
  strings:
    $key_5a0c = { 0d 7e [2] 3f 5c [2] 39 69 [2] 17 69 [2] 28 75 }

  condition:
    any of them
}