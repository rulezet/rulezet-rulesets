rule TTP_XOR_WriteProcessMemory_579f {
  strings:
    $key_579f = { 00 ed [2] 32 cf [2] 34 fa [2] 1a fa [2] 25 e6 }

  condition:
    any of them
}