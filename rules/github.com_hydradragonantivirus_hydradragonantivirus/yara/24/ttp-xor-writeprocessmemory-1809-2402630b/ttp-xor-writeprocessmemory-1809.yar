rule TTP_XOR_WriteProcessMemory_1809 {
  strings:
    $key_1809 = { 4f 7b [2] 7d 59 [2] 7b 6c [2] 55 6c [2] 6a 70 }

  condition:
    any of them
}