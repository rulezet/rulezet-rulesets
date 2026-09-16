rule TTP_XOR_WriteProcessMemory_f014 {
  strings:
    $key_f014 = { a7 66 [2] 95 44 [2] 93 71 [2] bd 71 [2] 82 6d }

  condition:
    any of them
}