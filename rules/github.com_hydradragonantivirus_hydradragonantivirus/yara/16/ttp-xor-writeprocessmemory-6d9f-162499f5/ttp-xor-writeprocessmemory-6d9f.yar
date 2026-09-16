rule TTP_XOR_WriteProcessMemory_6d9f {
  strings:
    $key_6d9f = { 3a ed [2] 08 cf [2] 0e fa [2] 20 fa [2] 1f e6 }

  condition:
    any of them
}