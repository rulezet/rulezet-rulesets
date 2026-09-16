rule TTP_XOR_WriteProcessMemory_789f {
  strings:
    $key_789f = { 2f ed [2] 1d cf [2] 1b fa [2] 35 fa [2] 0a e6 }

  condition:
    any of them
}