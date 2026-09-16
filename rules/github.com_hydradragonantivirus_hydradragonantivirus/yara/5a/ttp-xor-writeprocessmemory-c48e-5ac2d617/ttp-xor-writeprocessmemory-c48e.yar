rule TTP_XOR_WriteProcessMemory_c48e {
  strings:
    $key_c48e = { 93 fc [2] a1 de [2] a7 eb [2] 89 eb [2] b6 f7 }

  condition:
    any of them
}