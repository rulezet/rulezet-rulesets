rule TTP_XOR_WriteProcessMemory_59bd {
  strings:
    $key_59bd = { 0e cf [2] 3c ed [2] 3a d8 [2] 14 d8 [2] 2b c4 }

  condition:
    any of them
}