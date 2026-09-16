rule TTP_XOR_WriteProcessMemory_8e9f {
  strings:
    $key_8e9f = { d9 ed [2] eb cf [2] ed fa [2] c3 fa [2] fc e6 }

  condition:
    any of them
}