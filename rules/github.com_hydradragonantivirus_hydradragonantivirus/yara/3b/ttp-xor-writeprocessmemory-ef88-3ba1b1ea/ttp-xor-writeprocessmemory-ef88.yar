rule TTP_XOR_WriteProcessMemory_ef88 {
  strings:
    $key_ef88 = { b8 fa [2] 8a d8 [2] 8c ed [2] a2 ed [2] 9d f1 }

  condition:
    any of them
}