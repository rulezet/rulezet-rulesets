rule TTP_XOR_WriteProcessMemory_14f6 {
  strings:
    $key_14f6 = { 43 84 [2] 71 a6 [2] 77 93 [2] 59 93 [2] 66 8f }

  condition:
    any of them
}