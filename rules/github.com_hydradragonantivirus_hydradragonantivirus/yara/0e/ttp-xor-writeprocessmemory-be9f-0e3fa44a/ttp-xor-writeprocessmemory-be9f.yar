rule TTP_XOR_WriteProcessMemory_be9f {
  strings:
    $key_be9f = { e9 ed [2] db cf [2] dd fa [2] f3 fa [2] cc e6 }

  condition:
    any of them
}