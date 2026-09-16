rule TTP_XOR_WriteProcessMemory_ee9f {
  strings:
    $key_ee9f = { b9 ed [2] 8b cf [2] 8d fa [2] a3 fa [2] 9c e6 }

  condition:
    any of them
}