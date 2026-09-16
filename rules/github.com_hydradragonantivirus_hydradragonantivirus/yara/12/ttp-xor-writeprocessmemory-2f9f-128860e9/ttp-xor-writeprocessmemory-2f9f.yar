rule TTP_XOR_WriteProcessMemory_2f9f {
  strings:
    $key_2f9f = { 78 ed [2] 4a cf [2] 4c fa [2] 62 fa [2] 5d e6 }

  condition:
    any of them
}