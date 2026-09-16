rule TTP_XOR_WriteProcessMemory_89e8 {
  strings:
    $key_89e8 = { de 9a [2] ec b8 [2] ea 8d [2] c4 8d [2] fb 91 }

  condition:
    any of them
}