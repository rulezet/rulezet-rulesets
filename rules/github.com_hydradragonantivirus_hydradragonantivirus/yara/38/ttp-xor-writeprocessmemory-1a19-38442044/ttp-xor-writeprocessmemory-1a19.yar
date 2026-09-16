rule TTP_XOR_WriteProcessMemory_1a19 {
  strings:
    $key_1a19 = { 4d 6b [2] 7f 49 [2] 79 7c [2] 57 7c [2] 68 60 }

  condition:
    any of them
}