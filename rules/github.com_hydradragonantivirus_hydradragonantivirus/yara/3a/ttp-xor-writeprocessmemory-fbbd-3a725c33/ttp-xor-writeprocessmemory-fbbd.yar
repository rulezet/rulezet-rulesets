rule TTP_XOR_WriteProcessMemory_fbbd {
  strings:
    $key_fbbd = { ac cf [2] 9e ed [2] 98 d8 [2] b6 d8 [2] 89 c4 }

  condition:
    any of them
}