rule TTP_XOR_WriteProcessMemory_8fba {
  strings:
    $key_8fba = { d8 c8 [2] ea ea [2] ec df [2] c2 df [2] fd c3 }

  condition:
    any of them
}