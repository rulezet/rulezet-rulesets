rule TTP_XOR_WriteProcessMemory_389f {
  strings:
    $key_389f = { 6f ed [2] 5d cf [2] 5b fa [2] 75 fa [2] 4a e6 }

  condition:
    any of them
}