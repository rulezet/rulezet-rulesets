rule TTP_XOR_WriteProcessMemory_73bd {
  strings:
    $key_73bd = { 24 cf [2] 16 ed [2] 10 d8 [2] 3e d8 [2] 01 c4 }

  condition:
    any of them
}