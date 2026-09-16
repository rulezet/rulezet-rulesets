rule TTP_XOR_WriteProcessMemory_269f {
  strings:
    $key_269f = { 71 ed [2] 43 cf [2] 45 fa [2] 6b fa [2] 54 e6 }

  condition:
    any of them
}