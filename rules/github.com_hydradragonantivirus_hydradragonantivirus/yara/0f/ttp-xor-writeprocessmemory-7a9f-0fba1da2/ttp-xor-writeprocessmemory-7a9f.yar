rule TTP_XOR_WriteProcessMemory_7a9f {
  strings:
    $key_7a9f = { 2d ed [2] 1f cf [2] 19 fa [2] 37 fa [2] 08 e6 }

  condition:
    any of them
}