rule TTP_XOR_WriteProcessMemory_625b {
  strings:
    $key_625b = { 35 29 [2] 07 0b [2] 01 3e [2] 2f 3e [2] 10 22 }

  condition:
    any of them
}