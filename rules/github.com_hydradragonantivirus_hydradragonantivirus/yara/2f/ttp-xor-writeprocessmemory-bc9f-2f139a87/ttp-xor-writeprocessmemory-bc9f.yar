rule TTP_XOR_WriteProcessMemory_bc9f {
  strings:
    $key_bc9f = { eb ed [2] d9 cf [2] df fa [2] f1 fa [2] ce e6 }

  condition:
    any of them
}