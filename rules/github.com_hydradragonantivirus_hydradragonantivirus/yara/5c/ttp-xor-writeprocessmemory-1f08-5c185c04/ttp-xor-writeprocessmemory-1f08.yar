rule TTP_XOR_WriteProcessMemory_1f08 {
  strings:
    $key_1f08 = { 48 7a [2] 7a 58 [2] 7c 6d [2] 52 6d [2] 6d 71 }

  condition:
    any of them
}