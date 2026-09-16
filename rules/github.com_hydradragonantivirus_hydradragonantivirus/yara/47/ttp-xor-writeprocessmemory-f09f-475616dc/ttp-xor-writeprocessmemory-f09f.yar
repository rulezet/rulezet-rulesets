rule TTP_XOR_WriteProcessMemory_f09f {
  strings:
    $key_f09f = { a7 ed [2] 95 cf [2] 93 fa [2] bd fa [2] 82 e6 }

  condition:
    any of them
}