rule TTP_XOR_WriteProcessMemory_64bd {
  strings:
    $key_64bd = { 33 cf [2] 01 ed [2] 07 d8 [2] 29 d8 [2] 16 c4 }

  condition:
    any of them
}