rule TTP_XOR_WriteProcessMemory_b1bd {
  strings:
    $key_b1bd = { e6 cf [2] d4 ed [2] d2 d8 [2] fc d8 [2] c3 c4 }

  condition:
    any of them
}