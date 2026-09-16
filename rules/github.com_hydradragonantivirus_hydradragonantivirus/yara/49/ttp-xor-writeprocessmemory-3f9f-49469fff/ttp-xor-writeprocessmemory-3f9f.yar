rule TTP_XOR_WriteProcessMemory_3f9f {
  strings:
    $key_3f9f = { 68 ed [2] 5a cf [2] 5c fa [2] 72 fa [2] 4d e6 }

  condition:
    any of them
}