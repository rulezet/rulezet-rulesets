rule TTP_XOR_WriteProcessMemory_a9a8 {
  strings:
    $key_a9a8 = { fe da [2] cc f8 [2] ca cd [2] e4 cd [2] db d1 }

  condition:
    any of them
}