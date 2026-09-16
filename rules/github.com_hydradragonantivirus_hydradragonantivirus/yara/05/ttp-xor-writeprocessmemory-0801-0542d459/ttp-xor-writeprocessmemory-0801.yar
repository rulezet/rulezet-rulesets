rule TTP_XOR_WriteProcessMemory_0801 {
  strings:
    $key_0801 = { 5f 73 [2] 6d 51 [2] 6b 64 [2] 45 64 [2] 7a 78 }

  condition:
    any of them
}