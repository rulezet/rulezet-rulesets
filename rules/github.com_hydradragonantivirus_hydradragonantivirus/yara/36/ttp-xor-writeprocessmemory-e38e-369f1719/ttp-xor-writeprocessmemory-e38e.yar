rule TTP_XOR_WriteProcessMemory_e38e {
  strings:
    $key_e38e = { b4 fc [2] 86 de [2] 80 eb [2] ae eb [2] 91 f7 }

  condition:
    any of them
}