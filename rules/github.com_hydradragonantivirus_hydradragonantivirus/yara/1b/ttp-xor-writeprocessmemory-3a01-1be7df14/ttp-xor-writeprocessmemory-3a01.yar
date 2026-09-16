rule TTP_XOR_WriteProcessMemory_3a01 {
  strings:
    $key_3a01 = { 6d 73 [2] 5f 51 [2] 59 64 [2] 77 64 [2] 48 78 }

  condition:
    any of them
}