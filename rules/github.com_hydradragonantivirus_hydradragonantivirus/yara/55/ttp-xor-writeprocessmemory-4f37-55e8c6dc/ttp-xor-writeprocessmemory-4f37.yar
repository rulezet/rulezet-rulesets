rule TTP_XOR_WriteProcessMemory_4f37 {
  strings:
    $key_4f37 = { 18 45 [2] 2a 67 [2] 2c 52 [2] 02 52 [2] 3d 4e }

  condition:
    any of them
}