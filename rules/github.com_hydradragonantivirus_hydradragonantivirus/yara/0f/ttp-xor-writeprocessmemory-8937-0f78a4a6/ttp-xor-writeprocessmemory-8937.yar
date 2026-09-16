rule TTP_XOR_WriteProcessMemory_8937 {
  strings:
    $key_8937 = { de 45 [2] ec 67 [2] ea 52 [2] c4 52 [2] fb 4e }

  condition:
    any of them
}