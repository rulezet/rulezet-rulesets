rule TTP_XOR_WriteProcessMemory_d044 {
  strings:
    $key_d044 = { 87 36 [2] b5 14 [2] b3 21 [2] 9d 21 [2] a2 3d }

  condition:
    any of them
}