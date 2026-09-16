rule TTP_XOR_WriteProcessMemory_dcbd {
  strings:
    $key_dcbd = { 8b cf [2] b9 ed [2] bf d8 [2] 91 d8 [2] ae c4 }

  condition:
    any of them
}