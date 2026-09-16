rule TTP_XOR_WriteProcessMemory_759f {
  strings:
    $key_759f = { 22 ed [2] 10 cf [2] 16 fa [2] 38 fa [2] 07 e6 }

  condition:
    any of them
}