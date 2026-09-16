rule TTP_XOR_WriteProcessMemory_8fce {
  strings:
    $key_8fce = { d8 bc [2] ea 9e [2] ec ab [2] c2 ab [2] fd b7 }

  condition:
    any of them
}