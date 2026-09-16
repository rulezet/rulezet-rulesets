rule TTP_XOR_WriteProcessMemory_db9f {
  strings:
    $key_db9f = { 8c ed [2] be cf [2] b8 fa [2] 96 fa [2] a9 e6 }

  condition:
    any of them
}