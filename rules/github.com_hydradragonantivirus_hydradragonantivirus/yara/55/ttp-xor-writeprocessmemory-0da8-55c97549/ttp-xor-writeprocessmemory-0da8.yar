rule TTP_XOR_WriteProcessMemory_0da8 {
  strings:
    $key_0da8 = { 5a da [2] 68 f8 [2] 6e cd [2] 40 cd [2] 7f d1 }

  condition:
    any of them
}