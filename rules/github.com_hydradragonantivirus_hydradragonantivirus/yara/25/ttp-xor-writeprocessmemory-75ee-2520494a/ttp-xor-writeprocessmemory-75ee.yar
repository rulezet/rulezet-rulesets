rule TTP_XOR_WriteProcessMemory_75ee {
  strings:
    $key_75ee = { 22 9c [2] 10 be [2] 16 8b [2] 38 8b [2] 07 97 }

  condition:
    any of them
}