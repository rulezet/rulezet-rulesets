rule TTP_XOR_WriteProcessMemory_153c {
  strings:
    $key_153c = { 42 4e [2] 70 6c [2] 76 59 [2] 58 59 [2] 67 45 }

  condition:
    any of them
}