rule TTP_XOR_WriteProcessMemory_2d34 {
  strings:
    $key_2d34 = { 7a 46 [2] 48 64 [2] 4e 51 [2] 60 51 [2] 5f 4d }

  condition:
    any of them
}