rule TTP_XOR_WriteProcessMemory_e7bd {
  strings:
    $key_e7bd = { b0 cf [2] 82 ed [2] 84 d8 [2] aa d8 [2] 95 c4 }

  condition:
    any of them
}