rule TTP_XOR_WriteProcessMemory_28b3 {
  strings:
    $key_28b3 = { 7f c1 [2] 4d e3 [2] 4b d6 [2] 65 d6 [2] 5a ca }

  condition:
    any of them
}