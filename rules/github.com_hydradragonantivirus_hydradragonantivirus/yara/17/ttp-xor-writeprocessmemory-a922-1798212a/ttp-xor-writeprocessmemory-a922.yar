rule TTP_XOR_WriteProcessMemory_a922 {
  strings:
    $key_a922 = { fe 50 [2] cc 72 [2] ca 47 [2] e4 47 [2] db 5b }

  condition:
    any of them
}