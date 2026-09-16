rule TTP_XOR_WriteProcessMemory_3c08 {
  strings:
    $key_3c08 = { 6b 7a [2] 59 58 [2] 5f 6d [2] 71 6d [2] 4e 71 }

  condition:
    any of them
}