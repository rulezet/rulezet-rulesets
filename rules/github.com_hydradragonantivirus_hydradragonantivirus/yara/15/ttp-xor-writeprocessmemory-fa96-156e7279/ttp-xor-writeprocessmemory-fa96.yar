rule TTP_XOR_WriteProcessMemory_fa96 {
  strings:
    $key_fa96 = { ad e4 [2] 9f c6 [2] 99 f3 [2] b7 f3 [2] 88 ef }

  condition:
    any of them
}