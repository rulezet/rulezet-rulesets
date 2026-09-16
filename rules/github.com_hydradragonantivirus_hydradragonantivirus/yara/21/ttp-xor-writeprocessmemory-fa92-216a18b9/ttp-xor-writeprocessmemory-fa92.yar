rule TTP_XOR_WriteProcessMemory_fa92 {
  strings:
    $key_fa92 = { ad e0 [2] 9f c2 [2] 99 f7 [2] b7 f7 [2] 88 eb }

  condition:
    any of them
}