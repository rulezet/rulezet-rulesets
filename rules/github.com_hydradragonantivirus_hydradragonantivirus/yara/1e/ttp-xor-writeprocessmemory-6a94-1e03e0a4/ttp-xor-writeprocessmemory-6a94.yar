rule TTP_XOR_WriteProcessMemory_6a94 {
  strings:
    $key_6a94 = { 3d e6 [2] 0f c4 [2] 09 f1 [2] 27 f1 [2] 18 ed }

  condition:
    any of them
}