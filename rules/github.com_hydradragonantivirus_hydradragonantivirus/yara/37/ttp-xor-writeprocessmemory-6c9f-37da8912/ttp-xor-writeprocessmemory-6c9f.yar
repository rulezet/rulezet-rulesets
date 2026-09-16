rule TTP_XOR_WriteProcessMemory_6c9f {
  strings:
    $key_6c9f = { 3b ed [2] 09 cf [2] 0f fa [2] 21 fa [2] 1e e6 }

  condition:
    any of them
}