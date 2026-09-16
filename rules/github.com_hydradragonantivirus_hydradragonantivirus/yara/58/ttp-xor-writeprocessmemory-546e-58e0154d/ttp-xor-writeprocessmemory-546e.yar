rule TTP_XOR_WriteProcessMemory_546e {
  strings:
    $key_546e = { 03 1c [2] 31 3e [2] 37 0b [2] 19 0b [2] 26 17 }

  condition:
    any of them
}