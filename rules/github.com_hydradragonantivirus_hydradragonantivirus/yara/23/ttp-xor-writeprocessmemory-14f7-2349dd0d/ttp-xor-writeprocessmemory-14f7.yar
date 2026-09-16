rule TTP_XOR_WriteProcessMemory_14f7 {
  strings:
    $key_14f7 = { 43 85 [2] 71 a7 [2] 77 92 [2] 59 92 [2] 66 8e }

  condition:
    any of them
}