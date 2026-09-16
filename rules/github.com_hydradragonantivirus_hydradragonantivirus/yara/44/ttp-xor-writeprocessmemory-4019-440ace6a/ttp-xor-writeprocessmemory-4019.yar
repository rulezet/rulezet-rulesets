rule TTP_XOR_WriteProcessMemory_4019 {
  strings:
    $key_4019 = { 17 6b [2] 25 49 [2] 23 7c [2] 0d 7c [2] 32 60 }

  condition:
    any of them
}