rule TTP_XOR_WriteProcessMemory_8fca {
  strings:
    $key_8fca = { d8 b8 [2] ea 9a [2] ec af [2] c2 af [2] fd b3 }

  condition:
    any of them
}