rule TTP_XOR_WriteProcessMemory_89c4 {
  strings:
    $key_89c4 = { de b6 [2] ec 94 [2] ea a1 [2] c4 a1 [2] fb bd }

  condition:
    any of them
}