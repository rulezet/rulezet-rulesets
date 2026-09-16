rule TTP_XOR_WriteProcessMemory_e99f {
  strings:
    $key_e99f = { be ed [2] 8c cf [2] 8a fa [2] a4 fa [2] 9b e6 }

  condition:
    any of them
}