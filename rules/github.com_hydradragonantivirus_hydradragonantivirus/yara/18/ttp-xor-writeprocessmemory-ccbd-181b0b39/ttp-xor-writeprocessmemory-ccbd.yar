rule TTP_XOR_WriteProcessMemory_ccbd {
  strings:
    $key_ccbd = { 9b cf [2] a9 ed [2] af d8 [2] 81 d8 [2] be c4 }

  condition:
    any of them
}