rule TTP_XOR_WriteProcessMemory_3d61 {
  strings:
    $key_3d61 = { 6a 13 [2] 58 31 [2] 5e 04 [2] 70 04 [2] 4f 18 }

  condition:
    any of them
}