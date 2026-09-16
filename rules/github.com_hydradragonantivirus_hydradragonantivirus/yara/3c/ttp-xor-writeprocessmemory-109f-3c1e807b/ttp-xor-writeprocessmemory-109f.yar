rule TTP_XOR_WriteProcessMemory_109f {
  strings:
    $key_109f = { 47 ed [2] 75 cf [2] 73 fa [2] 5d fa [2] 62 e6 }

  condition:
    any of them
}