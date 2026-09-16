rule TTP_XOR_WriteProcessMemory_22bd {
  strings:
    $key_22bd = { 75 cf [2] 47 ed [2] 41 d8 [2] 6f d8 [2] 50 c4 }

  condition:
    any of them
}