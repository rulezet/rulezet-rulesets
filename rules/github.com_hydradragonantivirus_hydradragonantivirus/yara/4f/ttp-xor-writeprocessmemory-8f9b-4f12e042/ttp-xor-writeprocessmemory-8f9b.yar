rule TTP_XOR_WriteProcessMemory_8f9b {
  strings:
    $key_8f9b = { d8 e9 [2] ea cb [2] ec fe [2] c2 fe [2] fd e2 }

  condition:
    any of them
}