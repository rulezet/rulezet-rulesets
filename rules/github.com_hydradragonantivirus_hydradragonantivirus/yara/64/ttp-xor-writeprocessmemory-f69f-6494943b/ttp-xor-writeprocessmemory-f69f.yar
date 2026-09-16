rule TTP_XOR_WriteProcessMemory_f69f {
  strings:
    $key_f69f = { a1 ed [2] 93 cf [2] 95 fa [2] bb fa [2] 84 e6 }

  condition:
    any of them
}