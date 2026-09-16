rule TTP_XOR_WriteProcessMemory_009f {
  strings:
    $key_009f = { 57 ed [2] 65 cf [2] 63 fa [2] 4d fa [2] 72 e6 }

  condition:
    any of them
}