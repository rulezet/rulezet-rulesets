rule TTP_XOR_WriteProcessMemory_fb88 {
  strings:
    $key_fb88 = { ac fa [2] 9e d8 [2] 98 ed [2] b6 ed [2] 89 f1 }

  condition:
    any of them
}