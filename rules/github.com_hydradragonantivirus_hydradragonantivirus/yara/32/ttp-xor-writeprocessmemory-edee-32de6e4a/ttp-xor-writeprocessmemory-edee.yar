rule TTP_XOR_WriteProcessMemory_edee {
  strings:
    $key_edee = { ba 9c [2] 88 be [2] 8e 8b [2] a0 8b [2] 9f 97 }

  condition:
    any of them
}