rule TTP_XOR_WriteProcessMemory_fa88 {
  strings:
    $key_fa88 = { ad fa [2] 9f d8 [2] 99 ed [2] b7 ed [2] 88 f1 }

  condition:
    any of them
}