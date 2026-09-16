rule TTP_XOR_WriteProcessMemory_5e9f {
  strings:
    $key_5e9f = { 09 ed [2] 3b cf [2] 3d fa [2] 13 fa [2] 2c e6 }

  condition:
    any of them
}