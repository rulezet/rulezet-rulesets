rule TTP_XOR_WriteProcessMemory_06bd {
  strings:
    $key_06bd = { 51 cf [2] 63 ed [2] 65 d8 [2] 4b d8 [2] 74 c4 }

  condition:
    any of them
}