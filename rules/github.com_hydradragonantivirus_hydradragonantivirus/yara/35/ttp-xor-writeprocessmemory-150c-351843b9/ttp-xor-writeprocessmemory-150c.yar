rule TTP_XOR_WriteProcessMemory_150c {
  strings:
    $key_150c = { 42 7e [2] 70 5c [2] 76 69 [2] 58 69 [2] 67 75 }

  condition:
    any of them
}