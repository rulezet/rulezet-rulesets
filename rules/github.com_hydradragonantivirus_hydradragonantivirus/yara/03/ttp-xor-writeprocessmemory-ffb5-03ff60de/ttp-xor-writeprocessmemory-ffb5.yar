rule TTP_XOR_WriteProcessMemory_ffb5 {
  strings:
    $key_ffb5 = { a8 c7 [2] 9a e5 [2] 9c d0 [2] b2 d0 [2] 8d cc }

  condition:
    any of them
}