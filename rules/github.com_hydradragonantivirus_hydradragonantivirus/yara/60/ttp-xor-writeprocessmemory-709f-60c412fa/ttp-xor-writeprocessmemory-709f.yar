rule TTP_XOR_WriteProcessMemory_709f {
  strings:
    $key_709f = { 27 ed [2] 15 cf [2] 13 fa [2] 3d fa [2] 02 e6 }

  condition:
    any of them
}