rule TTP_XOR_WriteProcessMemory_3c01 {
  strings:
    $key_3c01 = { 6b 73 [2] 59 51 [2] 5f 64 [2] 71 64 [2] 4e 78 }

  condition:
    any of them
}