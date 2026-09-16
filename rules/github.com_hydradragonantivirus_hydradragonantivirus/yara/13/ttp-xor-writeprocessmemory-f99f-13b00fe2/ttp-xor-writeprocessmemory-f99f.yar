rule TTP_XOR_WriteProcessMemory_f99f {
  strings:
    $key_f99f = { ae ed [2] 9c cf [2] 9a fa [2] b4 fa [2] 8b e6 }

  condition:
    any of them
}