rule TTP_XOR_WriteProcessMemory_17ee {
  strings:
    $key_17ee = { 40 9c [2] 72 be [2] 74 8b [2] 5a 8b [2] 65 97 }

  condition:
    any of them
}