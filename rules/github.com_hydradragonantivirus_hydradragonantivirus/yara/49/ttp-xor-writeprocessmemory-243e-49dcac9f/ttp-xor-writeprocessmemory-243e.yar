rule TTP_XOR_WriteProcessMemory_243e {
  strings:
    $key_243e = { 73 4c [2] 41 6e [2] 47 5b [2] 69 5b [2] 56 47 }

  condition:
    any of them
}