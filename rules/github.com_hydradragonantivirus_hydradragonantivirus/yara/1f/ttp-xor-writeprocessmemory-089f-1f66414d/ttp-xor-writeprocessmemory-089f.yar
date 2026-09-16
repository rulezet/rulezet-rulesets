rule TTP_XOR_WriteProcessMemory_089f {
  strings:
    $key_089f = { 5f ed [2] 6d cf [2] 6b fa [2] 45 fa [2] 7a e6 }

  condition:
    any of them
}