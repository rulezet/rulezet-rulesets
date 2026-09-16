rule TTP_XOR_WriteProcessMemory_2209 {
  strings:
    $key_2209 = { 75 7b [2] 47 59 [2] 41 6c [2] 6f 6c [2] 50 70 }

  condition:
    any of them
}