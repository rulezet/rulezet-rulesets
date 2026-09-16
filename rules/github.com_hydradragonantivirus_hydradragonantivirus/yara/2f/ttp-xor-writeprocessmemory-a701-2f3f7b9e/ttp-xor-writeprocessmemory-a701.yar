rule TTP_XOR_WriteProcessMemory_a701 {
  strings:
    $key_a701 = { f0 73 [2] c2 51 [2] c4 64 [2] ea 64 [2] d5 78 }

  condition:
    any of them
}