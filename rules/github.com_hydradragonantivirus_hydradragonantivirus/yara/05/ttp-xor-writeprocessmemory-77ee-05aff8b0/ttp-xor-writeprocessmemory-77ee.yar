rule TTP_XOR_WriteProcessMemory_77ee {
  strings:
    $key_77ee = { 20 9c [2] 12 be [2] 14 8b [2] 3a 8b [2] 05 97 }

  condition:
    any of them
}