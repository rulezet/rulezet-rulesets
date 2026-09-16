rule TTP_XOR_WriteProcessMemory_75bd {
  strings:
    $key_75bd = { 22 cf [2] 10 ed [2] 16 d8 [2] 38 d8 [2] 07 c4 }

  condition:
    any of them
}