rule TTP_XOR_WriteProcessMemory_27ee {
  strings:
    $key_27ee = { 70 9c [2] 42 be [2] 44 8b [2] 6a 8b [2] 55 97 }

  condition:
    any of them
}