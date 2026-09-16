rule TTP_XOR_WriteProcessMemory_7501 {
  strings:
    $key_7501 = { 22 73 [2] 10 51 [2] 16 64 [2] 38 64 [2] 07 78 }

  condition:
    any of them
}