rule TTP_XOR_WriteProcessMemory_349f {
  strings:
    $key_349f = { 63 ed [2] 51 cf [2] 57 fa [2] 79 fa [2] 46 e6 }

  condition:
    any of them
}