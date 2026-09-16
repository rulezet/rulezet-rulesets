rule TTP_XOR_WriteProcessMemory_ef08 {
  strings:
    $key_ef08 = { b8 7a [2] 8a 58 [2] 8c 6d [2] a2 6d [2] 9d 71 }

  condition:
    any of them
}