rule TTP_XOR_WriteProcessMemory_34bd {
  strings:
    $key_34bd = { 63 cf [2] 51 ed [2] 57 d8 [2] 79 d8 [2] 46 c4 }

  condition:
    any of them
}