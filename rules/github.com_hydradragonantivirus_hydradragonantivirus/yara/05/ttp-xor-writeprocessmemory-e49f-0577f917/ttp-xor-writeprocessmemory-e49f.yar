rule TTP_XOR_WriteProcessMemory_e49f {
  strings:
    $key_e49f = { b3 ed [2] 81 cf [2] 87 fa [2] a9 fa [2] 96 e6 }

  condition:
    any of them
}