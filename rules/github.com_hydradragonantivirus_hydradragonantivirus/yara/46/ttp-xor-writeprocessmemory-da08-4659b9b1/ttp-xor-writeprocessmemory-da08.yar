rule TTP_XOR_WriteProcessMemory_da08 {
  strings:
    $key_da08 = { 8d 7a [2] bf 58 [2] b9 6d [2] 97 6d [2] a8 71 }

  condition:
    any of them
}