rule TTP_XOR_WriteProcessMemory_2de9 {
  strings:
    $key_2de9 = { 7a 9b [2] 48 b9 [2] 4e 8c [2] 60 8c [2] 5f 90 }

  condition:
    any of them
}