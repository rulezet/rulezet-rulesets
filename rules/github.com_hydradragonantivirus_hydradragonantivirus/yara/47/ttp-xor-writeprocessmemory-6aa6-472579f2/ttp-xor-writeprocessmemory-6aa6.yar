rule TTP_XOR_WriteProcessMemory_6aa6 {
  strings:
    $key_6aa6 = { 3d d4 [2] 0f f6 [2] 09 c3 [2] 27 c3 [2] 18 df }

  condition:
    any of them
}