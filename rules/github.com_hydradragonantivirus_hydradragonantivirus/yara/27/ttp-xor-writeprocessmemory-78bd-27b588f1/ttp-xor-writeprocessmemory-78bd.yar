rule TTP_XOR_WriteProcessMemory_78bd {
  strings:
    $key_78bd = { 2f cf [2] 1d ed [2] 1b d8 [2] 35 d8 [2] 0a c4 }

  condition:
    any of them
}