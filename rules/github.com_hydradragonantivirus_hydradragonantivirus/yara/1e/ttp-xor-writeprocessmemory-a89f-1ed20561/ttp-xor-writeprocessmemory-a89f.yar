rule TTP_XOR_WriteProcessMemory_a89f {
  strings:
    $key_a89f = { ff ed [2] cd cf [2] cb fa [2] e5 fa [2] da e6 }

  condition:
    any of them
}