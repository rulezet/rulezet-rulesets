rule TTP_XOR_WriteProcessMemory_8d9f {
  strings:
    $key_8d9f = { da ed [2] e8 cf [2] ee fa [2] c0 fa [2] ff e6 }

  condition:
    any of them
}