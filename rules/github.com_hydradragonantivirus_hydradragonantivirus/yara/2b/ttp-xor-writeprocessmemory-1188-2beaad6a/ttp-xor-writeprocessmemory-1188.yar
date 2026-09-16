rule TTP_XOR_WriteProcessMemory_1188 {
  strings:
    $key_1188 = { 46 fa [2] 74 d8 [2] 72 ed [2] 5c ed [2] 63 f1 }

  condition:
    any of them
}