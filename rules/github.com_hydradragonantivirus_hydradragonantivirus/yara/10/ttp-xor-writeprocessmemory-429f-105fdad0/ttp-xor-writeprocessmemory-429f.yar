rule TTP_XOR_WriteProcessMemory_429f {
  strings:
    $key_429f = { 15 ed [2] 27 cf [2] 21 fa [2] 0f fa [2] 30 e6 }

  condition:
    any of them
}