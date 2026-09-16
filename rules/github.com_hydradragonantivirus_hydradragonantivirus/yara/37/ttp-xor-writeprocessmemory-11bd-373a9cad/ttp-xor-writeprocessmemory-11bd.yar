rule TTP_XOR_WriteProcessMemory_11bd {
  strings:
    $key_11bd = { 46 cf [2] 74 ed [2] 72 d8 [2] 5c d8 [2] 63 c4 }

  condition:
    any of them
}