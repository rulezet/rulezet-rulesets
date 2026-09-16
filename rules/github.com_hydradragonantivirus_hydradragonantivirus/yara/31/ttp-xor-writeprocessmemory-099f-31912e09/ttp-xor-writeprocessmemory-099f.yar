rule TTP_XOR_WriteProcessMemory_099f {
  strings:
    $key_099f = { 5e ed [2] 6c cf [2] 6a fa [2] 44 fa [2] 7b e6 }

  condition:
    any of them
}