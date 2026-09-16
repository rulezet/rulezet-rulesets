rule TTP_XOR_WriteProcessMemory_89dd {
  strings:
    $key_89dd = { de af [2] ec 8d [2] ea b8 [2] c4 b8 [2] fb a4 }

  condition:
    any of them
}