rule TTP_XOR_WriteProcessMemory_6244 {
  strings:
    $key_6244 = { 35 36 [2] 07 14 [2] 01 21 [2] 2f 21 [2] 10 3d }

  condition:
    any of them
}