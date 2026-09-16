rule TTP_XOR_WriteProcessMemory_1e9f {
  strings:
    $key_1e9f = { 49 ed [2] 7b cf [2] 7d fa [2] 53 fa [2] 6c e6 }

  condition:
    any of them
}