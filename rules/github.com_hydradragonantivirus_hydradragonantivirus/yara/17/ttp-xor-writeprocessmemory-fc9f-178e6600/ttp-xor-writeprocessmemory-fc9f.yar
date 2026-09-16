rule TTP_XOR_WriteProcessMemory_fc9f {
  strings:
    $key_fc9f = { ab ed [2] 99 cf [2] 9f fa [2] b1 fa [2] 8e e6 }

  condition:
    any of them
}