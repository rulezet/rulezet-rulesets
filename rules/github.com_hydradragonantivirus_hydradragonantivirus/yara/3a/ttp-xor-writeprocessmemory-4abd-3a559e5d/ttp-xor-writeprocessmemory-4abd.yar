rule TTP_XOR_WriteProcessMemory_4abd {
  strings:
    $key_4abd = { 1d cf [2] 2f ed [2] 29 d8 [2] 07 d8 [2] 38 c4 }

  condition:
    any of them
}