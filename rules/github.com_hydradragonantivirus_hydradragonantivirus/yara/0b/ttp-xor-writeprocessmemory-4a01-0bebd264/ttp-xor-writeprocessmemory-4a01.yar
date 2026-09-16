rule TTP_XOR_WriteProcessMemory_4a01 {
  strings:
    $key_4a01 = { 1d 73 [2] 2f 51 [2] 29 64 [2] 07 64 [2] 38 78 }

  condition:
    any of them
}