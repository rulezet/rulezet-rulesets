rule TTP_XOR_WriteProcessMemory_89d0 {
  strings:
    $key_89d0 = { de a2 [2] ec 80 [2] ea b5 [2] c4 b5 [2] fb a9 }

  condition:
    any of them
}