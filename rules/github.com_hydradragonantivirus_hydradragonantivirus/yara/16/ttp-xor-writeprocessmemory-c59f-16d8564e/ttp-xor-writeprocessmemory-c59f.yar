rule TTP_XOR_WriteProcessMemory_c59f {
  strings:
    $key_c59f = { 92 ed [2] a0 cf [2] a6 fa [2] 88 fa [2] b7 e6 }

  condition:
    any of them
}