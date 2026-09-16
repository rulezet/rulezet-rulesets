rule TTP_XOR_WriteProcessMemory_30a8 {
  strings:
    $key_30a8 = { 67 da [2] 55 f8 [2] 53 cd [2] 7d cd [2] 42 d1 }

  condition:
    any of them
}