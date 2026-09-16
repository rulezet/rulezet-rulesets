rule TTP_XOR_WriteProcessMemory_61bd {
  strings:
    $key_61bd = { 36 cf [2] 04 ed [2] 02 d8 [2] 2c d8 [2] 13 c4 }

  condition:
    any of them
}