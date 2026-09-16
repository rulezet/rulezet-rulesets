rule TTP_XOR_WriteProcessMemory_a974 {
  strings:
    $key_a974 = { fe 06 [2] cc 24 [2] ca 11 [2] e4 11 [2] db 0d }

  condition:
    any of them
}