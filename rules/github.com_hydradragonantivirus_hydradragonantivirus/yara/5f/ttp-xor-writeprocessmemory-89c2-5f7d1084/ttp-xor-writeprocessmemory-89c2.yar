rule TTP_XOR_WriteProcessMemory_89c2 {
  strings:
    $key_89c2 = { de b0 [2] ec 92 [2] ea a7 [2] c4 a7 [2] fb bb }

  condition:
    any of them
}