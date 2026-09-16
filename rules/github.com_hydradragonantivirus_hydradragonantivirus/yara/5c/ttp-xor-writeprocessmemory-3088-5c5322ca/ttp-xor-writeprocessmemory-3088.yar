rule TTP_XOR_WriteProcessMemory_3088 {
  strings:
    $key_3088 = { 67 fa [2] 55 d8 [2] 53 ed [2] 7d ed [2] 42 f1 }

  condition:
    any of them
}