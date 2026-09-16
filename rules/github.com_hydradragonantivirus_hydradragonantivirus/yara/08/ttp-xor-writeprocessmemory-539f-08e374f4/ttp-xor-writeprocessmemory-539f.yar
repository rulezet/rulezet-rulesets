rule TTP_XOR_WriteProcessMemory_539f {
  strings:
    $key_539f = { 04 ed [2] 36 cf [2] 30 fa [2] 1e fa [2] 21 e6 }

  condition:
    any of them
}