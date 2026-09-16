rule TTP_XOR_WriteProcessMemory_7ba8 {
  strings:
    $key_7ba8 = { 2c da [2] 1e f8 [2] 18 cd [2] 36 cd [2] 09 d1 }

  condition:
    any of them
}