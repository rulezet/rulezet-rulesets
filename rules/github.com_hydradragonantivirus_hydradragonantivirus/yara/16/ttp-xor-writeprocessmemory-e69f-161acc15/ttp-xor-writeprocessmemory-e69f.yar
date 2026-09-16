rule TTP_XOR_WriteProcessMemory_e69f {
  strings:
    $key_e69f = { b1 ed [2] 83 cf [2] 85 fa [2] ab fa [2] 94 e6 }

  condition:
    any of them
}