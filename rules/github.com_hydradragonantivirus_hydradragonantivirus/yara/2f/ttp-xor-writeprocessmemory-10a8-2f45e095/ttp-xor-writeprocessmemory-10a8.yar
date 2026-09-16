rule TTP_XOR_WriteProcessMemory_10a8 {
  strings:
    $key_10a8 = { 47 da [2] 75 f8 [2] 73 cd [2] 5d cd [2] 62 d1 }

  condition:
    any of them
}