rule TTP_XOR_WriteProcessMemory_c39f {
  strings:
    $key_c39f = { 94 ed [2] a6 cf [2] a0 fa [2] 8e fa [2] b1 e6 }

  condition:
    any of them
}