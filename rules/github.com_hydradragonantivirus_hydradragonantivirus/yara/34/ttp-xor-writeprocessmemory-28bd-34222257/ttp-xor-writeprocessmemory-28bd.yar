rule TTP_XOR_WriteProcessMemory_28bd {
  strings:
    $key_28bd = { 7f cf [2] 4d ed [2] 4b d8 [2] 65 d8 [2] 5a c4 }

  condition:
    any of them
}