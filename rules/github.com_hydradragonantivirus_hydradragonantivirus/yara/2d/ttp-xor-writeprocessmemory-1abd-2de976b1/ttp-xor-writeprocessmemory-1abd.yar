rule TTP_XOR_WriteProcessMemory_1abd {
  strings:
    $key_1abd = { 4d cf [2] 7f ed [2] 79 d8 [2] 57 d8 [2] 68 c4 }

  condition:
    any of them
}