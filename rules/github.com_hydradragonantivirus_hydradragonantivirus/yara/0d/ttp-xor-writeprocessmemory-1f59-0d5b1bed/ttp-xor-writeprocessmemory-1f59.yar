rule TTP_XOR_WriteProcessMemory_1f59 {
  strings:
    $key_1f59 = { 48 2b [2] 7a 09 [2] 7c 3c [2] 52 3c [2] 6d 20 }

  condition:
    any of them
}