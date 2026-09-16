rule TTP_XOR_WriteProcessMemory_aa9f {
  strings:
    $key_aa9f = { fd ed [2] cf cf [2] c9 fa [2] e7 fa [2] d8 e6 }

  condition:
    any of them
}