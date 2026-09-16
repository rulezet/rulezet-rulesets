rule TTP_XOR_WriteProcessMemory_8957 {
  strings:
    $key_8957 = { de 25 [2] ec 07 [2] ea 32 [2] c4 32 [2] fb 2e }

  condition:
    any of them
}