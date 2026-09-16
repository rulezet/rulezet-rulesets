rule TTP_XOR_WriteProcessMemory_27bd {
  strings:
    $key_27bd = { 70 cf [2] 42 ed [2] 44 d8 [2] 6a d8 [2] 55 c4 }

  condition:
    any of them
}