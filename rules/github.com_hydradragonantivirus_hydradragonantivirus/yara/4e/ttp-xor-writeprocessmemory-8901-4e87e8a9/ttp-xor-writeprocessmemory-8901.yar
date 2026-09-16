rule TTP_XOR_WriteProcessMemory_8901 {
  strings:
    $key_8901 = { de 73 [2] ec 51 [2] ea 64 [2] c4 64 [2] fb 78 }

  condition:
    any of them
}