rule TTP_XOR_WriteProcessMemory_65ee {
  strings:
    $key_65ee = { 32 9c [2] 00 be [2] 06 8b [2] 28 8b [2] 17 97 }

  condition:
    any of them
}