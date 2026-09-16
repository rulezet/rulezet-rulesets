rule TTP_XOR_WriteProcessMemory_8fea {
  strings:
    $key_8fea = { d8 98 [2] ea ba [2] ec 8f [2] c2 8f [2] fd 93 }

  condition:
    any of them
}