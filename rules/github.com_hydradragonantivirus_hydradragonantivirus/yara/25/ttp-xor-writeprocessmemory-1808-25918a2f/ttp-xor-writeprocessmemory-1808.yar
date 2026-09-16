rule TTP_XOR_WriteProcessMemory_1808 {
  strings:
    $key_1808 = { 4f 7a [2] 7d 58 [2] 7b 6d [2] 55 6d [2] 6a 71 }

  condition:
    any of them
}