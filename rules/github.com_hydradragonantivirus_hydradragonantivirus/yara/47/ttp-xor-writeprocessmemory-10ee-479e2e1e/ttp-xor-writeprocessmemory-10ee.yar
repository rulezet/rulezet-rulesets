rule TTP_XOR_WriteProcessMemory_10ee {
  strings:
    $key_10ee = { 47 9c [2] 75 be [2] 73 8b [2] 5d 8b [2] 62 97 }

  condition:
    any of them
}