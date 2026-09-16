rule TTP_XOR_WriteProcessMemory_4fd2 {
  strings:
    $key_4fd2 = { 18 a0 [2] 2a 82 [2] 2c b7 [2] 02 b7 [2] 3d ab }

  condition:
    any of them
}