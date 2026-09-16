rule TTP_XOR_WriteProcessMemory_eb88 {
  strings:
    $key_eb88 = { bc fa [2] 8e d8 [2] 88 ed [2] a6 ed [2] 99 f1 }

  condition:
    any of them
}