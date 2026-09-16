rule TTP_XOR_WriteProcessMemory_dafe {
  strings:
    $key_dafe = { 8d 8c [2] bf ae [2] b9 9b [2] 97 9b [2] a8 87 }

  condition:
    any of them
}