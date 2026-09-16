rule TTP_XOR_WriteProcessMemory_0f9f {
  strings:
    $key_0f9f = { 58 ed [2] 6a cf [2] 6c fa [2] 42 fa [2] 7d e6 }

  condition:
    any of them
}