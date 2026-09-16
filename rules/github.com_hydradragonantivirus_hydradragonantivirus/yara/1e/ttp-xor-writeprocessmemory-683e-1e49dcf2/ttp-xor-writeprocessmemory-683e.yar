rule TTP_XOR_WriteProcessMemory_683e {
  strings:
    $key_683e = { 3f 4c [2] 0d 6e [2] 0b 5b [2] 25 5b [2] 1a 47 }

  condition:
    any of them
}