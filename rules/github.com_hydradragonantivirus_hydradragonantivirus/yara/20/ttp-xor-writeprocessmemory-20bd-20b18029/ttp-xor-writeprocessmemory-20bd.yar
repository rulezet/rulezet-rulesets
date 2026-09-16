rule TTP_XOR_WriteProcessMemory_20bd {
  strings:
    $key_20bd = { 77 cf [2] 45 ed [2] 43 d8 [2] 6d d8 [2] 52 c4 }

  condition:
    any of them
}