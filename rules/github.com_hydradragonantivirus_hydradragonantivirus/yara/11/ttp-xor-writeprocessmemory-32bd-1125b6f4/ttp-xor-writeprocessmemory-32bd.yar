rule TTP_XOR_WriteProcessMemory_32bd {
  strings:
    $key_32bd = { 65 cf [2] 57 ed [2] 51 d8 [2] 7f d8 [2] 40 c4 }

  condition:
    any of them
}