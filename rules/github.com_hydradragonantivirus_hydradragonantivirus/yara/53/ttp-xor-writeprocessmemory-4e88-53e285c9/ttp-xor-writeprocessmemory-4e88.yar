rule TTP_XOR_WriteProcessMemory_4e88 {
  strings:
    $key_4e88 = { 19 fa [2] 2b d8 [2] 2d ed [2] 03 ed [2] 3c f1 }

  condition:
    any of them
}