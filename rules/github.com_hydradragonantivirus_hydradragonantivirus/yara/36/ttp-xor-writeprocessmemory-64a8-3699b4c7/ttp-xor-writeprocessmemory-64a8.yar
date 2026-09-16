rule TTP_XOR_WriteProcessMemory_64a8 {
  strings:
    $key_64a8 = { 33 da [2] 01 f8 [2] 07 cd [2] 29 cd [2] 16 d1 }

  condition:
    any of them
}