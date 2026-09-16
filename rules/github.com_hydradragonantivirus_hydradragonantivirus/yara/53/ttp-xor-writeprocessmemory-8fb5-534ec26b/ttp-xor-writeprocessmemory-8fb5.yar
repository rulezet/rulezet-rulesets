rule TTP_XOR_WriteProcessMemory_8fb5 {
  strings:
    $key_8fb5 = { d8 c7 [2] ea e5 [2] ec d0 [2] c2 d0 [2] fd cc }

  condition:
    any of them
}