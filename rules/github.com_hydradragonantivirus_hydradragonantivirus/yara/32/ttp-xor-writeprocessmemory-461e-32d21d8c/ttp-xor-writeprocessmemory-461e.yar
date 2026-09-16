rule TTP_XOR_WriteProcessMemory_461e {
  strings:
    $key_461e = { 11 6c [2] 23 4e [2] 25 7b [2] 0b 7b [2] 34 67 }

  condition:
    any of them
}