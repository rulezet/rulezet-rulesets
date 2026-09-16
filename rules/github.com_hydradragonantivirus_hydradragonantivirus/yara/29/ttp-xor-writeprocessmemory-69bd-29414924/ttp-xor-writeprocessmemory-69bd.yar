rule TTP_XOR_WriteProcessMemory_69bd {
  strings:
    $key_69bd = { 3e cf [2] 0c ed [2] 0a d8 [2] 24 d8 [2] 1b c4 }

  condition:
    any of them
}