rule TTP_XOR_WriteProcessMemory_7d9f {
  strings:
    $key_7d9f = { 2a ed [2] 18 cf [2] 1e fa [2] 30 fa [2] 0f e6 }

  condition:
    any of them
}