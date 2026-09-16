rule TTP_XOR_WriteProcessMemory_cb9f {
  strings:
    $key_cb9f = { 9c ed [2] ae cf [2] a8 fa [2] 86 fa [2] b9 e6 }

  condition:
    any of them
}