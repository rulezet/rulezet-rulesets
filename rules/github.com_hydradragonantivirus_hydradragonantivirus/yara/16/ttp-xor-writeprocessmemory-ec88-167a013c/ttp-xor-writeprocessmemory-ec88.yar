rule TTP_XOR_WriteProcessMemory_ec88 {
  strings:
    $key_ec88 = { bb fa [2] 89 d8 [2] 8f ed [2] a1 ed [2] 9e f1 }

  condition:
    any of them
}