rule TTP_XOR_WriteProcessMemory_89e3 {
  strings:
    $key_89e3 = { de 91 [2] ec b3 [2] ea 86 [2] c4 86 [2] fb 9a }

  condition:
    any of them
}