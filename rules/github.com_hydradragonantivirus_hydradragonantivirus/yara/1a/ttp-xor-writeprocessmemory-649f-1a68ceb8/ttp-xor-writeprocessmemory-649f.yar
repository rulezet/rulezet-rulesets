rule TTP_XOR_WriteProcessMemory_649f {
  strings:
    $key_649f = { 33 ed [2] 01 cf [2] 07 fa [2] 29 fa [2] 16 e6 }

  condition:
    any of them
}