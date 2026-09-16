rule TTP_XOR_WriteProcessMemory_18bd {
  strings:
    $key_18bd = { 4f cf [2] 7d ed [2] 7b d8 [2] 55 d8 [2] 6a c4 }

  condition:
    any of them
}