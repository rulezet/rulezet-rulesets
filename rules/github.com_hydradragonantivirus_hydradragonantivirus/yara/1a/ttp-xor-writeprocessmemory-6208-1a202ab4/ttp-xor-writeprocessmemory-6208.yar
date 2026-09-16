rule TTP_XOR_WriteProcessMemory_6208 {
  strings:
    $key_6208 = { 35 7a [2] 07 58 [2] 01 6d [2] 2f 6d [2] 10 71 }

  condition:
    any of them
}