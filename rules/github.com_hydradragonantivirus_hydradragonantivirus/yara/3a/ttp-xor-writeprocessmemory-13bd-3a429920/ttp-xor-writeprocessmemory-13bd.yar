rule TTP_XOR_WriteProcessMemory_13bd {
  strings:
    $key_13bd = { 44 cf [2] 76 ed [2] 70 d8 [2] 5e d8 [2] 61 c4 }

  condition:
    any of them
}