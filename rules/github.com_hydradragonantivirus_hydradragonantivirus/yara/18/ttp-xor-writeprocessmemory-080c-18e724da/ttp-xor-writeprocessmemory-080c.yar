rule TTP_XOR_WriteProcessMemory_080c {
  strings:
    $key_080c = { 5f 7e [2] 6d 5c [2] 6b 69 [2] 45 69 [2] 7a 75 }

  condition:
    any of them
}