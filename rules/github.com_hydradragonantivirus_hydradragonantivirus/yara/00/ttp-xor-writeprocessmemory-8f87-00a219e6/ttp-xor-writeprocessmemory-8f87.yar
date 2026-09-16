rule TTP_XOR_WriteProcessMemory_8f87 {
  strings:
    $key_8f87 = { d8 f5 [2] ea d7 [2] ec e2 [2] c2 e2 [2] fd fe }

  condition:
    any of them
}