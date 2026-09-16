rule TTP_XOR_WriteProcessMemory_e29f {
  strings:
    $key_e29f = { b5 ed [2] 87 cf [2] 81 fa [2] af fa [2] 90 e6 }

  condition:
    any of them
}