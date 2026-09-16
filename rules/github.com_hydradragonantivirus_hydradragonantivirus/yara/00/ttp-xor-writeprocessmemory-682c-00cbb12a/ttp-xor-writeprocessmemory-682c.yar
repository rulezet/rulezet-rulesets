rule TTP_XOR_WriteProcessMemory_682c {
  strings:
    $key_682c = { 3f 5e [2] 0d 7c [2] 0b 49 [2] 25 49 [2] 1a 55 }

  condition:
    any of them
}