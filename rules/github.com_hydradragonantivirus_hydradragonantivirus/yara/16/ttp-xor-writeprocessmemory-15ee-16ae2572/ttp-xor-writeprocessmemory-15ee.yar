rule TTP_XOR_WriteProcessMemory_15ee {
  strings:
    $key_15ee = { 42 9c [2] 70 be [2] 76 8b [2] 58 8b [2] 67 97 }

  condition:
    any of them
}