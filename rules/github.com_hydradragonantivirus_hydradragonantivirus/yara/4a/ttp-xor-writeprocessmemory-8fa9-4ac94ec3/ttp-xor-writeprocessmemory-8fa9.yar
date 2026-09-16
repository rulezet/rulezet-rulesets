rule TTP_XOR_WriteProcessMemory_8fa9 {
  strings:
    $key_8fa9 = { d8 db [2] ea f9 [2] ec cc [2] c2 cc [2] fd d0 }

  condition:
    any of them
}