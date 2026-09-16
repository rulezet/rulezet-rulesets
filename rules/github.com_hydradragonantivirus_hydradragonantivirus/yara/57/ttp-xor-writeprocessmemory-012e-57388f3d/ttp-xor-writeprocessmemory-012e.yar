rule TTP_XOR_WriteProcessMemory_012e {
  strings:
    $key_012e = { 56 5c [2] 64 7e [2] 62 4b [2] 4c 4b [2] 73 57 }

  condition:
    any of them
}