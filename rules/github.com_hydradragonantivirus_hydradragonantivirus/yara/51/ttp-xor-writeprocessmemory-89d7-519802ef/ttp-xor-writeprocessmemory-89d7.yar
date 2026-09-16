rule TTP_XOR_WriteProcessMemory_89d7 {
  strings:
    $key_89d7 = { de a5 [2] ec 87 [2] ea b2 [2] c4 b2 [2] fb ae }

  condition:
    any of them
}