rule TTP_XOR_WriteProcessMemory_a9b8 {
  strings:
    $key_a9b8 = { fe ca [2] cc e8 [2] ca dd [2] e4 dd [2] db c1 }

  condition:
    any of them
}