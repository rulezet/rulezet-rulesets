rule TTP_XOR_WriteProcessMemory_cd9f {
  strings:
    $key_cd9f = { 9a ed [2] a8 cf [2] ae fa [2] 80 fa [2] bf e6 }

  condition:
    any of them
}