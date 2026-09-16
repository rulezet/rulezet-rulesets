rule TTP_XOR_WriteProcessMemory_529f {
  strings:
    $key_529f = { 05 ed [2] 37 cf [2] 31 fa [2] 1f fa [2] 20 e6 }

  condition:
    any of them
}