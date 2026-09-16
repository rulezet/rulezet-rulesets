rule TTP_XOR_WriteProcessMemory_039f {
  strings:
    $key_039f = { 54 ed [2] 66 cf [2] 60 fa [2] 4e fa [2] 71 e6 }

  condition:
    any of them
}