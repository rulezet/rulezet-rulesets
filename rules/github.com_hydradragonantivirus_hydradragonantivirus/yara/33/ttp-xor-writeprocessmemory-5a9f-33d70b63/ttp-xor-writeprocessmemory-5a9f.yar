rule TTP_XOR_WriteProcessMemory_5a9f {
  strings:
    $key_5a9f = { 0d ed [2] 3f cf [2] 39 fa [2] 17 fa [2] 28 e6 }

  condition:
    any of them
}