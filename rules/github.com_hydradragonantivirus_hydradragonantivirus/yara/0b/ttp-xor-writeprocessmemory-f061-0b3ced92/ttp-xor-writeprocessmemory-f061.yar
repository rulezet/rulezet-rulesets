rule TTP_XOR_WriteProcessMemory_f061 {
  strings:
    $key_f061 = { a7 13 [2] 95 31 [2] 93 04 [2] bd 04 [2] 82 18 }

  condition:
    any of them
}