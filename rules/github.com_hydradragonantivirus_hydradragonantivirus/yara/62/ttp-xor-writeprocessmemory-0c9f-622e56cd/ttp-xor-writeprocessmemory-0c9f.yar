rule TTP_XOR_WriteProcessMemory_0c9f {
  strings:
    $key_0c9f = { 5b ed [2] 69 cf [2] 6f fa [2] 41 fa [2] 7e e6 }

  condition:
    any of them
}