rule TTP_XOR_WriteProcessMemory_4fb2 {
  strings:
    $key_4fb2 = { 18 c0 [2] 2a e2 [2] 2c d7 [2] 02 d7 [2] 3d cb }

  condition:
    any of them
}