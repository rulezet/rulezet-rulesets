rule TTP_XOR_WriteProcessMemory_072c {
  strings:
    $key_072c = { 50 5e [2] 62 7c [2] 64 49 [2] 4a 49 [2] 75 55 }

  condition:
    any of them
}