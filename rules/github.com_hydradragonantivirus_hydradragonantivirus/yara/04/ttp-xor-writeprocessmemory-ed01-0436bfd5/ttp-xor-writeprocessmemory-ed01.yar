rule TTP_XOR_WriteProcessMemory_ed01 {
  strings:
    $key_ed01 = { ba 73 [2] 88 51 [2] 8e 64 [2] a0 64 [2] 9f 78 }

  condition:
    any of them
}