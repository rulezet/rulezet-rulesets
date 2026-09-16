rule TTP_XOR_WriteProcessMemory_dd97 {
  strings:
    $key_dd97 = { 8a e5 [2] b8 c7 [2] be f2 [2] 90 f2 [2] af ee }

  condition:
    any of them
}