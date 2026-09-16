rule TTP_XOR_WriteProcessMemory_439f {
  strings:
    $key_439f = { 14 ed [2] 26 cf [2] 20 fa [2] 0e fa [2] 31 e6 }

  condition:
    any of them
}