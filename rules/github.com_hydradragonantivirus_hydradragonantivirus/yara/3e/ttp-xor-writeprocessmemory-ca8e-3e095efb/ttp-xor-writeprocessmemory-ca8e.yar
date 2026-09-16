rule TTP_XOR_WriteProcessMemory_ca8e {
  strings:
    $key_ca8e = { 9d fc [2] af de [2] a9 eb [2] 87 eb [2] b8 f7 }

  condition:
    any of them
}