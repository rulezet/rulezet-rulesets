rule TTP_XOR_WriteProcessMemory_67ee {
  strings:
    $key_67ee = { 30 9c [2] 02 be [2] 04 8b [2] 2a 8b [2] 15 97 }

  condition:
    any of them
}