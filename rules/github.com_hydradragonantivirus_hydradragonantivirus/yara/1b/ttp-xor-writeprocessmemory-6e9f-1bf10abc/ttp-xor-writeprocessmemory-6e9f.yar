rule TTP_XOR_WriteProcessMemory_6e9f {
  strings:
    $key_6e9f = { 39 ed [2] 0b cf [2] 0d fa [2] 23 fa [2] 1c e6 }

  condition:
    any of them
}