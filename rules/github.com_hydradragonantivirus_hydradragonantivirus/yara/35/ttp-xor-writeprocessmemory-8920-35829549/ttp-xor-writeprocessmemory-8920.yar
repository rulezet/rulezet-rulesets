rule TTP_XOR_WriteProcessMemory_8920 {
  strings:
    $key_8920 = { de 52 [2] ec 70 [2] ea 45 [2] c4 45 [2] fb 59 }

  condition:
    any of them
}