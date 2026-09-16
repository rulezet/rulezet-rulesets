rule TTP_XOR_WriteProcessMemory_4fd0 {
  strings:
    $key_4fd0 = { 18 a2 [2] 2a 80 [2] 2c b5 [2] 02 b5 [2] 3d a9 }

  condition:
    any of them
}