rule TTP_XOR_WriteProcessMemory_41ee {
  strings:
    $key_41ee = { 16 9c [2] 24 be [2] 22 8b [2] 0c 8b [2] 33 97 }

  condition:
    any of them
}