rule TTP_XOR_WriteProcessMemory_4f24 {
  strings:
    $key_4f24 = { 18 56 [2] 2a 74 [2] 2c 41 [2] 02 41 [2] 3d 5d }

  condition:
    any of them
}