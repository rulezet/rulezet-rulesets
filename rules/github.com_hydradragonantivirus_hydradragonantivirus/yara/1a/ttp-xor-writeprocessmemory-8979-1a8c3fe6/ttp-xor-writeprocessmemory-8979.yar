rule TTP_XOR_WriteProcessMemory_8979 {
  strings:
    $key_8979 = { de 0b [2] ec 29 [2] ea 1c [2] c4 1c [2] fb 00 }

  condition:
    any of them
}