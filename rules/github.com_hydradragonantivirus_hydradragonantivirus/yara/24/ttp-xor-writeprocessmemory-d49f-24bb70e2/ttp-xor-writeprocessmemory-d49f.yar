rule TTP_XOR_WriteProcessMemory_d49f {
  strings:
    $key_d49f = { 83 ed [2] b1 cf [2] b7 fa [2] 99 fa [2] a6 e6 }

  condition:
    any of them
}