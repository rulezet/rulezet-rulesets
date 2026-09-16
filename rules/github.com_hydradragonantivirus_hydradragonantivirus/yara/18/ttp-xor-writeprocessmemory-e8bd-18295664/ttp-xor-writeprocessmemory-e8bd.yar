rule TTP_XOR_WriteProcessMemory_e8bd {
  strings:
    $key_e8bd = { bf cf [2] 8d ed [2] 8b d8 [2] a5 d8 [2] 9a c4 }

  condition:
    any of them
}