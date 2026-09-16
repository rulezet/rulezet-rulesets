rule TTP_XOR_WriteProcessMemory_6a93 {
  strings:
    $key_6a93 = { 3d e1 [2] 0f c3 [2] 09 f6 [2] 27 f6 [2] 18 ea }

  condition:
    any of them
}