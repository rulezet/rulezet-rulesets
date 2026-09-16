rule TTP_XOR_WriteProcessMemory_fa8e {
  strings:
    $key_fa8e = { ad fc [2] 9f de [2] 99 eb [2] b7 eb [2] 88 f7 }

  condition:
    any of them
}