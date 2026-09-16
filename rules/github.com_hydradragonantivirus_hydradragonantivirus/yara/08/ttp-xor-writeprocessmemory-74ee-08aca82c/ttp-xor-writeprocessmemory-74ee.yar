rule TTP_XOR_WriteProcessMemory_74ee {
  strings:
    $key_74ee = { 23 9c [2] 11 be [2] 17 8b [2] 39 8b [2] 06 97 }

  condition:
    any of them
}