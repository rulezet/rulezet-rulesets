rule TTP_XOR_WriteProcessMemory_ae9f {
  strings:
    $key_ae9f = { f9 ed [2] cb cf [2] cd fa [2] e3 fa [2] dc e6 }

  condition:
    any of them
}