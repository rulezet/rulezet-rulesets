rule TTP_XOR_WriteProcessMemory_3ee3 {
  strings:
    $key_3ee3 = { 69 91 [2] 5b b3 [2] 5d 86 [2] 73 86 [2] 4c 9a }

  condition:
    any of them
}