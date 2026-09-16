rule TTP_XOR_WriteProcessMemory_5388 {
  strings:
    $key_5388 = { 04 fa [2] 36 d8 [2] 30 ed [2] 1e ed [2] 21 f1 }

  condition:
    any of them
}