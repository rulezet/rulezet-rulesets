rule TTP_XOR_WriteProcessMemory_8923 {
  strings:
    $key_8923 = { de 51 [2] ec 73 [2] ea 46 [2] c4 46 [2] fb 5a }

  condition:
    any of them
}