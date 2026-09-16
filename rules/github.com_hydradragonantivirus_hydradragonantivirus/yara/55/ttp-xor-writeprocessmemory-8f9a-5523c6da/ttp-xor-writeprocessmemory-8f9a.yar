rule TTP_XOR_WriteProcessMemory_8f9a {
  strings:
    $key_8f9a = { d8 e8 [2] ea ca [2] ec ff [2] c2 ff [2] fd e3 }

  condition:
    any of them
}