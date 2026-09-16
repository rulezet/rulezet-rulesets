rule TTP_XOR_WriteProcessMemory_89c7 {
  strings:
    $key_89c7 = { de b5 [2] ec 97 [2] ea a2 [2] c4 a2 [2] fb be }

  condition:
    any of them
}