rule TTP_XOR_WriteProcessMemory_54ee {
  strings:
    $key_54ee = { 03 9c [2] 31 be [2] 37 8b [2] 19 8b [2] 26 97 }

  condition:
    any of them
}