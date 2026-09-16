rule TTP_XOR_WriteProcessMemory_8601 {
  strings:
    $key_8601 = { d1 73 [2] e3 51 [2] e5 64 [2] cb 64 [2] f4 78 }

  condition:
    any of them
}