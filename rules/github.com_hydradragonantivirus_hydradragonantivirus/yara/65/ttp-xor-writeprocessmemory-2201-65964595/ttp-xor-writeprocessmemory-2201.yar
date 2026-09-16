rule TTP_XOR_WriteProcessMemory_2201 {
  strings:
    $key_2201 = { 75 73 [2] 47 51 [2] 41 64 [2] 6f 64 [2] 50 78 }

  condition:
    any of them
}