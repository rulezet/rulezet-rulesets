rule TTP_XOR_WriteProcessMemory_599f {
  strings:
    $key_599f = { 0e ed [2] 3c cf [2] 3a fa [2] 14 fa [2] 2b e6 }

  condition:
    any of them
}