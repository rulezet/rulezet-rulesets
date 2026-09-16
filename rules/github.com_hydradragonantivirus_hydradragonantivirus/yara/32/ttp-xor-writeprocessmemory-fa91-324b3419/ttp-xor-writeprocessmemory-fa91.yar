rule TTP_XOR_WriteProcessMemory_fa91 {
  strings:
    $key_fa91 = { ad e3 [2] 9f c1 [2] 99 f4 [2] b7 f4 [2] 88 e8 }

  condition:
    any of them
}