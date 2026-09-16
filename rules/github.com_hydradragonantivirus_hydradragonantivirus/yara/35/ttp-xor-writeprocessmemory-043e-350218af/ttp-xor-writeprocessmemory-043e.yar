rule TTP_XOR_WriteProcessMemory_043e {
  strings:
    $key_043e = { 53 4c [2] 61 6e [2] 67 5b [2] 49 5b [2] 76 47 }

  condition:
    any of them
}