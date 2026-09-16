rule TTP_XOR_WriteProcessMemory_fa71 {
  strings:
    $key_fa71 = { ad 03 [2] 9f 21 [2] 99 14 [2] b7 14 [2] 88 08 }

  condition:
    any of them
}