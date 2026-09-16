rule TTP_XOR_WriteProcessMemory_72bd {
  strings:
    $key_72bd = { 25 cf [2] 17 ed [2] 11 d8 [2] 3f d8 [2] 00 c4 }

  condition:
    any of them
}