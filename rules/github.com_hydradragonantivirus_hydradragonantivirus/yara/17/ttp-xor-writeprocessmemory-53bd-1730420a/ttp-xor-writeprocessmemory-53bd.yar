rule TTP_XOR_WriteProcessMemory_53bd {
  strings:
    $key_53bd = { 04 cf [2] 36 ed [2] 30 d8 [2] 1e d8 [2] 21 c4 }

  condition:
    any of them
}