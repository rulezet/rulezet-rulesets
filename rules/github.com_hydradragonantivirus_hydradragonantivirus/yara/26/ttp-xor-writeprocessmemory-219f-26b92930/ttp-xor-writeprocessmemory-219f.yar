rule TTP_XOR_WriteProcessMemory_219f {
  strings:
    $key_219f = { 76 ed [2] 44 cf [2] 42 fa [2] 6c fa [2] 53 e6 }

  condition:
    any of them
}