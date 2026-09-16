rule TTP_XOR_WriteProcessMemory_689f {
  strings:
    $key_689f = { 3f ed [2] 0d cf [2] 0b fa [2] 25 fa [2] 1a e6 }

  condition:
    any of them
}