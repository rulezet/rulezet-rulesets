rule TTP_XOR_WriteProcessMemory_133e {
  strings:
    $key_133e = { 44 4c [2] 76 6e [2] 70 5b [2] 5e 5b [2] 61 47 }

  condition:
    any of them
}