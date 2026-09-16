rule TTP_XOR_WriteProcessMemory_eb9f {
  strings:
    $key_eb9f = { bc ed [2] 8e cf [2] 88 fa [2] a6 fa [2] 99 e6 }

  condition:
    any of them
}