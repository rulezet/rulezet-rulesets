rule TTP_XOR_WriteProcessMemory_163c {
  strings:
    $key_163c = { 41 4e [2] 73 6c [2] 75 59 [2] 5b 59 [2] 64 45 }

  condition:
    any of them
}