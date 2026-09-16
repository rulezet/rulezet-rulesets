rule TTP_XOR_WriteProcessMemory_e79f {
  strings:
    $key_e79f = { b0 ed [2] 82 cf [2] 84 fa [2] aa fa [2] 95 e6 }

  condition:
    any of them
}