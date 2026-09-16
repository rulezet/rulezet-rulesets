rule TTP_XOR_WriteProcessMemory_339f {
  strings:
    $key_339f = { 64 ed [2] 56 cf [2] 50 fa [2] 7e fa [2] 41 e6 }

  condition:
    any of them
}