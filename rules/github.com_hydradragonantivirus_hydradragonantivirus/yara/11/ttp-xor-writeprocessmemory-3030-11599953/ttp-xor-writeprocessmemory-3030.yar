rule TTP_XOR_WriteProcessMemory_3030 {
  strings:
    $key_3030 = { 67 42 [2] 55 60 [2] 53 55 [2] 7d 55 [2] 42 49 }

  condition:
    any of them
}