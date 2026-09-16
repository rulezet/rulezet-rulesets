rule TTP_XOR_WriteProcessMemory_44a8 {
  strings:
    $key_44a8 = { 13 da [2] 21 f8 [2] 27 cd [2] 09 cd [2] 36 d1 }

  condition:
    any of them
}