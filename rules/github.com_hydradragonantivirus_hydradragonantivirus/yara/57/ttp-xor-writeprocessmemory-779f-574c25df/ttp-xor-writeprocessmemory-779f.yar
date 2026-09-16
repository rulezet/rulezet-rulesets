rule TTP_XOR_WriteProcessMemory_779f {
  strings:
    $key_779f = { 20 ed [2] 12 cf [2] 14 fa [2] 3a fa [2] 05 e6 }

  condition:
    any of them
}