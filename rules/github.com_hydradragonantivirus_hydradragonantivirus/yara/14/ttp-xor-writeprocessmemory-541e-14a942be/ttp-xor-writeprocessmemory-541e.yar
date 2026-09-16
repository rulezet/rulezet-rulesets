rule TTP_XOR_WriteProcessMemory_541e {
  strings:
    $key_541e = { 03 6c [2] 31 4e [2] 37 7b [2] 19 7b [2] 26 67 }

  condition:
    any of them
}