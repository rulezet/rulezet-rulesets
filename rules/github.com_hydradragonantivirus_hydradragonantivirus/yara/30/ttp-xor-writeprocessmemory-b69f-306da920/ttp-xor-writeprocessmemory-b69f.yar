rule TTP_XOR_WriteProcessMemory_b69f {
  strings:
    $key_b69f = { e1 ed [2] d3 cf [2] d5 fa [2] fb fa [2] c4 e6 }

  condition:
    any of them
}