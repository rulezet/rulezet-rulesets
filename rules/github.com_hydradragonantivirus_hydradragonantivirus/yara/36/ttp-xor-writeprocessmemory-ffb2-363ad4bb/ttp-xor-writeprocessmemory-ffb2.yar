rule TTP_XOR_WriteProcessMemory_ffb2 {
  strings:
    $key_ffb2 = { a8 c0 [2] 9a e2 [2] 9c d7 [2] b2 d7 [2] 8d cb }

  condition:
    any of them
}