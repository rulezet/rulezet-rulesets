rule TTP_XOR_WriteProcessMemory_769f {
  strings:
    $key_769f = { 21 ed [2] 13 cf [2] 15 fa [2] 3b fa [2] 04 e6 }

  condition:
    any of them
}