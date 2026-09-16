rule TTP_XOR_WriteProcessMemory_af9f {
  strings:
    $key_af9f = { f8 ed [2] ca cf [2] cc fa [2] e2 fa [2] dd e6 }

  condition:
    any of them
}