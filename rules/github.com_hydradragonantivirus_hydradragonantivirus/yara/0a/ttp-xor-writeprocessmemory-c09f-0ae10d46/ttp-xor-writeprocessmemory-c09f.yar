rule TTP_XOR_WriteProcessMemory_c09f {
  strings:
    $key_c09f = { 97 ed [2] a5 cf [2] a3 fa [2] 8d fa [2] b2 e6 }

  condition:
    any of them
}