rule TTP_XOR_WriteProcessMemory_719f {
  strings:
    $key_719f = { 26 ed [2] 14 cf [2] 12 fa [2] 3c fa [2] 03 e6 }

  condition:
    any of them
}