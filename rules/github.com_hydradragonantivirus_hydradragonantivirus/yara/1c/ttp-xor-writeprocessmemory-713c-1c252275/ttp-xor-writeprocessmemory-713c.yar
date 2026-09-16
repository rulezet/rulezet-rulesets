rule TTP_XOR_WriteProcessMemory_713c {
  strings:
    $key_713c = { 26 4e [2] 14 6c [2] 12 59 [2] 3c 59 [2] 03 45 }

  condition:
    any of them
}