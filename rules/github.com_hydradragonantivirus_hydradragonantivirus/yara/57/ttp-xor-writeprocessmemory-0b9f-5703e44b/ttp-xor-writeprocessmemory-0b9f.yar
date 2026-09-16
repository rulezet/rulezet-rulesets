rule TTP_XOR_WriteProcessMemory_0b9f {
  strings:
    $key_0b9f = { 5c ed [2] 6e cf [2] 68 fa [2] 46 fa [2] 79 e6 }

  condition:
    any of them
}