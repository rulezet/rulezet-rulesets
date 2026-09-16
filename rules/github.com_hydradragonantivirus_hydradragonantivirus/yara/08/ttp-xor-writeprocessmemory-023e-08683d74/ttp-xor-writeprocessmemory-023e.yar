rule TTP_XOR_WriteProcessMemory_023e {
  strings:
    $key_023e = { 55 4c [2] 67 6e [2] 61 5b [2] 4f 5b [2] 70 47 }

  condition:
    any of them
}