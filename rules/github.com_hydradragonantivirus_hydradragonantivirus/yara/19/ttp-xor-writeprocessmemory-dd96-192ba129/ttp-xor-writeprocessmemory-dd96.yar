rule TTP_XOR_WriteProcessMemory_dd96 {
  strings:
    $key_dd96 = { 8a e4 [2] b8 c6 [2] be f3 [2] 90 f3 [2] af ef }

  condition:
    any of them
}