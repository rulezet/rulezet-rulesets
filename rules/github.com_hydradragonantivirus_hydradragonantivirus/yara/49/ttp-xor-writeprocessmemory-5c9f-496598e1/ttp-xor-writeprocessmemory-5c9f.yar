rule TTP_XOR_WriteProcessMemory_5c9f {
  strings:
    $key_5c9f = { 0b ed [2] 39 cf [2] 3f fa [2] 11 fa [2] 2e e6 }

  condition:
    any of them
}