rule TTP_XOR_WriteProcessMemory_ed9d {
  strings:
    $key_ed9d = { ba ef [2] 88 cd [2] 8e f8 [2] a0 f8 [2] 9f e4 }

  condition:
    any of them
}