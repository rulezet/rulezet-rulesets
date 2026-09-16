rule TTP_XOR_WriteProcessMemory_49bd {
  strings:
    $key_49bd = { 1e cf [2] 2c ed [2] 2a d8 [2] 04 d8 [2] 3b c4 }

  condition:
    any of them
}