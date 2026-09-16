rule TTP_XOR_WriteProcessMemory_8915 {
  strings:
    $key_8915 = { de 67 [2] ec 45 [2] ea 70 [2] c4 70 [2] fb 6c }

  condition:
    any of them
}