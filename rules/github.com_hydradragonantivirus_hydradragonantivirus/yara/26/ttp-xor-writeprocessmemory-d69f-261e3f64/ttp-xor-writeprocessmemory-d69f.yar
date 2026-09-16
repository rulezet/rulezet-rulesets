rule TTP_XOR_WriteProcessMemory_d69f {
  strings:
    $key_d69f = { 81 ed [2] b3 cf [2] b5 fa [2] 9b fa [2] a4 e6 }

  condition:
    any of them
}