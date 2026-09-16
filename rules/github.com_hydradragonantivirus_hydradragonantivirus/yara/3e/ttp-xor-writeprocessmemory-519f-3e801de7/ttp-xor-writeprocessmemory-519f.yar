rule TTP_XOR_WriteProcessMemory_519f {
  strings:
    $key_519f = { 06 ed [2] 34 cf [2] 32 fa [2] 1c fa [2] 23 e6 }

  condition:
    any of them
}