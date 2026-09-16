rule TTP_XOR_WriteProcessMemory_89c5 {
  strings:
    $key_89c5 = { de b7 [2] ec 95 [2] ea a0 [2] c4 a0 [2] fb bc }

  condition:
    any of them
}