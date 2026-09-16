rule TTP_XOR_WriteProcessMemory_b29f {
  strings:
    $key_b29f = { e5 ed [2] d7 cf [2] d1 fa [2] ff fa [2] c0 e6 }

  condition:
    any of them
}