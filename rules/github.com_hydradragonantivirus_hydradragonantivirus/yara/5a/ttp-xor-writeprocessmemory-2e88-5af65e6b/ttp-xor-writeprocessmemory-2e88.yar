rule TTP_XOR_WriteProcessMemory_2e88 {
  strings:
    $key_2e88 = { 79 fa [2] 4b d8 [2] 4d ed [2] 63 ed [2] 5c f1 }

  condition:
    any of them
}