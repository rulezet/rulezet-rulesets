rule TTP_XOR_WriteProcessMemory_c69f {
  strings:
    $key_c69f = { 91 ed [2] a3 cf [2] a5 fa [2] 8b fa [2] b4 e6 }

  condition:
    any of them
}