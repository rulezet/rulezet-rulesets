rule TTP_XOR_WriteProcessMemory_29bd {
  strings:
    $key_29bd = { 7e cf [2] 4c ed [2] 4a d8 [2] 64 d8 [2] 5b c4 }

  condition:
    any of them
}