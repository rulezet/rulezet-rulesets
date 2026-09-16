rule TTP_XOR_WriteProcessMemory_f5ee {
  strings:
    $key_f5ee = { a2 9c [2] 90 be [2] 96 8b [2] b8 8b [2] 87 97 }

  condition:
    any of them
}