rule TTP_XOR_WriteProcessMemory_ea88 {
  strings:
    $key_ea88 = { bd fa [2] 8f d8 [2] 89 ed [2] a7 ed [2] 98 f1 }

  condition:
    any of them
}