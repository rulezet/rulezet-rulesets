rule TTP_XOR_WriteProcessMemory_1f39 {
  strings:
    $key_1f39 = { 48 4b [2] 7a 69 [2] 7c 5c [2] 52 5c [2] 6d 40 }

  condition:
    any of them
}