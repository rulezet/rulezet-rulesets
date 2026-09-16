rule TTP_XOR_WriteProcessMemory_3208 {
  strings:
    $key_3208 = { 65 7a [2] 57 58 [2] 51 6d [2] 7f 6d [2] 40 71 }

  condition:
    any of them
}