rule TTP_XOR_WriteProcessMemory_0d9f {
  strings:
    $key_0d9f = { 5a ed [2] 68 cf [2] 6e fa [2] 40 fa [2] 7f e6 }

  condition:
    any of them
}