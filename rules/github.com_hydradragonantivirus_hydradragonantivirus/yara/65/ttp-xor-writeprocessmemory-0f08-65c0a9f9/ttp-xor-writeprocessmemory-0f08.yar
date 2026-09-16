rule TTP_XOR_WriteProcessMemory_0f08 {
  strings:
    $key_0f08 = { 58 7a [2] 6a 58 [2] 6c 6d [2] 42 6d [2] 7d 71 }

  condition:
    any of them
}