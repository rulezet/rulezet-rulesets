rule TTP_XOR_WriteProcessMemory_2f01 {
  strings:
    $key_2f01 = { 78 73 [2] 4a 51 [2] 4c 64 [2] 62 64 [2] 5d 78 }

  condition:
    any of them
}