rule TTP_XOR_WriteProcessMemory_1b9f {
  strings:
    $key_1b9f = { 4c ed [2] 7e cf [2] 78 fa [2] 56 fa [2] 69 e6 }

  condition:
    any of them
}