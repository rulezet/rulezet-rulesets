rule TTP_XOR_WriteProcessMemory_8925 {
  strings:
    $key_8925 = { de 57 [2] ec 75 [2] ea 40 [2] c4 40 [2] fb 5c }

  condition:
    any of them
}