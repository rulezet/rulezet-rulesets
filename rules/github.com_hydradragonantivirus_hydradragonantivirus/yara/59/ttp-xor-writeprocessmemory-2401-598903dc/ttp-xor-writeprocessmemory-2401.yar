rule TTP_XOR_WriteProcessMemory_2401 {
  strings:
    $key_2401 = { 73 73 [2] 41 51 [2] 47 64 [2] 69 64 [2] 56 78 }

  condition:
    any of them
}