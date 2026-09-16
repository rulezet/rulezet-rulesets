rule TTP_XOR_WriteProcessMemory_cb88 {
  strings:
    $key_cb88 = { 9c fa [2] ae d8 [2] a8 ed [2] 86 ed [2] b9 f1 }

  condition:
    any of them
}