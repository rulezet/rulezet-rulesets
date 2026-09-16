rule TTP_XOR_WriteProcessMemory_119f {
  strings:
    $key_119f = { 46 ed [2] 74 cf [2] 72 fa [2] 5c fa [2] 63 e6 }

  condition:
    any of them
}