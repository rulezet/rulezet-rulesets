rule TTP_XOR_WriteProcessMemory_a961 {
  strings:
    $key_a961 = { fe 13 [2] cc 31 [2] ca 04 [2] e4 04 [2] db 18 }

  condition:
    any of them
}