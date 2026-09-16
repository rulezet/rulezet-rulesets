rule TTP_XOR_WriteProcessMemory_8975 {
  strings:
    $key_8975 = { de 07 [2] ec 25 [2] ea 10 [2] c4 10 [2] fb 0c }

  condition:
    any of them
}