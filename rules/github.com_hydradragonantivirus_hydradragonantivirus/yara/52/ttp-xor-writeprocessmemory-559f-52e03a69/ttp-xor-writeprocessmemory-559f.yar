rule TTP_XOR_WriteProcessMemory_559f {
  strings:
    $key_559f = { 02 ed [2] 30 cf [2] 36 fa [2] 18 fa [2] 27 e6 }

  condition:
    any of them
}