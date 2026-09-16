rule TTP_XOR_WriteProcessMemory_3d01 {
  strings:
    $key_3d01 = { 6a 73 [2] 58 51 [2] 5e 64 [2] 70 64 [2] 4f 78 }

  condition:
    any of them
}