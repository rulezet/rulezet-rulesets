rule TTP_XOR_WriteProcessMemory_caf8 {
  strings:
    $key_caf8 = { 9d 8a [2] af a8 [2] a9 9d [2] 87 9d [2] b8 81 }

  condition:
    any of them
}