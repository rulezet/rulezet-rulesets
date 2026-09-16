rule TTP_XOR_WriteProcessMemory_27a8 {
  strings:
    $key_27a8 = { 70 da [2] 42 f8 [2] 44 cd [2] 6a cd [2] 55 d1 }

  condition:
    any of them
}