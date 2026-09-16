rule TTP_XOR_WriteProcessMemory_8f9f {
  strings:
    $key_8f9f = { d8 ed [2] ea cf [2] ec fa [2] c2 fa [2] fd e6 }

  condition:
    any of them
}