rule TTP_XOR_WriteProcessMemory_019f {
  strings:
    $key_019f = { 56 ed [2] 64 cf [2] 62 fa [2] 4c fa [2] 73 e6 }

  condition:
    any of them
}