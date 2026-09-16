rule TTP_XOR_WriteProcessMemory_659f {
  strings:
    $key_659f = { 32 ed [2] 00 cf [2] 06 fa [2] 28 fa [2] 17 e6 }

  condition:
    any of them
}