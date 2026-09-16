rule TTP_XOR_WriteProcessMemory_2a19 {
  strings:
    $key_2a19 = { 7d 6b [2] 4f 49 [2] 49 7c [2] 67 7c [2] 58 60 }

  condition:
    any of them
}