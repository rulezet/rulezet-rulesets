rule TTP_XOR_WriteProcessMemory_8e88 {
  strings:
    $key_8e88 = { d9 fa [2] eb d8 [2] ed ed [2] c3 ed [2] fc f1 }

  condition:
    any of them
}