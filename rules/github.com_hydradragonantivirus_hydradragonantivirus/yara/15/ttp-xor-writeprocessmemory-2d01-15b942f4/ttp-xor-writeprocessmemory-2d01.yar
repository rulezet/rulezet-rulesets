rule TTP_XOR_WriteProcessMemory_2d01 {
  strings:
    $key_2d01 = { 7a 73 [2] 48 51 [2] 4e 64 [2] 60 64 [2] 5f 78 }

  condition:
    any of them
}