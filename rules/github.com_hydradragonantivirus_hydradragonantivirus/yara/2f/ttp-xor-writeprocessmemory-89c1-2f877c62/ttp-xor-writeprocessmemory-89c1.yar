rule TTP_XOR_WriteProcessMemory_89c1 {
  strings:
    $key_89c1 = { de b3 [2] ec 91 [2] ea a4 [2] c4 a4 [2] fb b8 }

  condition:
    any of them
}