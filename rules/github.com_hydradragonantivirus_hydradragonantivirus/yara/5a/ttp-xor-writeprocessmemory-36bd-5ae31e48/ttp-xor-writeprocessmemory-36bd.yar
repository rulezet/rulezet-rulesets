rule TTP_XOR_WriteProcessMemory_36bd {
  strings:
    $key_36bd = { 61 cf [2] 53 ed [2] 55 d8 [2] 7b d8 [2] 44 c4 }

  condition:
    any of them
}