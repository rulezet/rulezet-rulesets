rule TTP_XOR_WriteProcessMemory_15bd {
  strings:
    $key_15bd = { 42 cf [2] 70 ed [2] 76 d8 [2] 58 d8 [2] 67 c4 }

  condition:
    any of them
}