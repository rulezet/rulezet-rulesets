rule TTP_XOR_WriteProcessMemory_189f {
  strings:
    $key_189f = { 4f ed [2] 7d cf [2] 7b fa [2] 55 fa [2] 6a e6 }

  condition:
    any of them
}