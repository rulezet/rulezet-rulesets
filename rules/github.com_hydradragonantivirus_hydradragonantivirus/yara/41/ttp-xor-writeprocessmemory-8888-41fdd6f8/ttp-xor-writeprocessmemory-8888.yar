rule TTP_XOR_WriteProcessMemory_8888 {
  strings:
    $key_8888 = { df fa [2] ed d8 [2] eb ed [2] c5 ed [2] fa f1 }

  condition:
    any of them
}