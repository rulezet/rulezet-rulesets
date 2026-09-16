rule TTP_XOR_WriteProcessMemory_58bd {
  strings:
    $key_58bd = { 0f cf [2] 3d ed [2] 3b d8 [2] 15 d8 [2] 2a c4 }

  condition:
    any of them
}