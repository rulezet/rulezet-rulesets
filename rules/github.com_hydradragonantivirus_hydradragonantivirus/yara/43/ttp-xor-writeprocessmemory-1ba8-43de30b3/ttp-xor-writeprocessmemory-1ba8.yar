rule TTP_XOR_WriteProcessMemory_1ba8 {
  strings:
    $key_1ba8 = { 4c da [2] 7e f8 [2] 78 cd [2] 56 cd [2] 69 d1 }

  condition:
    any of them
}