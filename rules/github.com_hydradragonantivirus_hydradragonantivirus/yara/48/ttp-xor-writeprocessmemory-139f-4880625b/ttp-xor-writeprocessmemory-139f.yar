rule TTP_XOR_WriteProcessMemory_139f {
  strings:
    $key_139f = { 44 ed [2] 76 cf [2] 70 fa [2] 5e fa [2] 61 e6 }

  condition:
    any of them
}