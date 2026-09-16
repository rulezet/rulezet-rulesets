rule TTP_XOR_WriteProcessMemory_fa97 {
  strings:
    $key_fa97 = { ad e5 [2] 9f c7 [2] 99 f2 [2] b7 f2 [2] 88 ee }

  condition:
    any of them
}