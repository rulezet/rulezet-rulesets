rule TTP_XOR_WriteProcessMemory_7001 {
  strings:
    $key_7001 = { 27 73 [2] 15 51 [2] 13 64 [2] 3d 64 [2] 02 78 }

  condition:
    any of them
}