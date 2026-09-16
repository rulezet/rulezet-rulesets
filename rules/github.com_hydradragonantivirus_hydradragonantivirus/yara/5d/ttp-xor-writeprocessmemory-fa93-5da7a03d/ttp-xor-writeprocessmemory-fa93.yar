rule TTP_XOR_WriteProcessMemory_fa93 {
  strings:
    $key_fa93 = { ad e1 [2] 9f c3 [2] 99 f6 [2] b7 f6 [2] 88 ea }

  condition:
    any of them
}