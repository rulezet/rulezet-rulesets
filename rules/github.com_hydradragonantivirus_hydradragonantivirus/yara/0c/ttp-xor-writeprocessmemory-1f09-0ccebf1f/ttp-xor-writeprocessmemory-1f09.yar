rule TTP_XOR_WriteProcessMemory_1f09 {
  strings:
    $key_1f09 = { 48 7b [2] 7a 59 [2] 7c 6c [2] 52 6c [2] 6d 70 }

  condition:
    any of them
}