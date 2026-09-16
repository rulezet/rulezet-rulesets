rule TTP_XOR_WriteProcessMemory_46ee {
  strings:
    $key_46ee = { 11 9c [2] 23 be [2] 25 8b [2] 0b 8b [2] 34 97 }

  condition:
    any of them
}