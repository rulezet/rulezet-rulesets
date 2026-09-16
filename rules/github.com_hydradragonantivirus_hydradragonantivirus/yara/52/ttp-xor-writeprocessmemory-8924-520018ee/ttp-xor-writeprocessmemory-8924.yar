rule TTP_XOR_WriteProcessMemory_8924 {
  strings:
    $key_8924 = { de 56 [2] ec 74 [2] ea 41 [2] c4 41 [2] fb 5d }

  condition:
    any of them
}