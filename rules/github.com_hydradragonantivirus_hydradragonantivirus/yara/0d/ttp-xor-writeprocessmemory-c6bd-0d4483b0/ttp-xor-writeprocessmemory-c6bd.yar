rule TTP_XOR_WriteProcessMemory_c6bd {
  strings:
    $key_c6bd = { 91 cf [2] a3 ed [2] a5 d8 [2] 8b d8 [2] b4 c4 }

  condition:
    any of them
}