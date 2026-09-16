rule TTP_XOR_WriteProcessMemory_d19f {
  strings:
    $key_d19f = { 86 ed [2] b4 cf [2] b2 fa [2] 9c fa [2] a3 e6 }

  condition:
    any of them
}