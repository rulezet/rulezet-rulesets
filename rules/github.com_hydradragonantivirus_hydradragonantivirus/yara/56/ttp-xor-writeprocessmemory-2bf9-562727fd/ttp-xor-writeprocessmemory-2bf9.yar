rule TTP_XOR_WriteProcessMemory_2bf9 {
  strings:
    $key_2bf9 = { 7c 8b [2] 4e a9 [2] 48 9c [2] 66 9c [2] 59 80 }

  condition:
    any of them
}