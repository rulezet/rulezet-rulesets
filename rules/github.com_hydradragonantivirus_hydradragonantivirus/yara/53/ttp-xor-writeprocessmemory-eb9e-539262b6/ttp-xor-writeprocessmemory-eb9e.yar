rule TTP_XOR_WriteProcessMemory_eb9e {
  strings:
    $key_eb9e = { bc ec [2] 8e ce [2] 88 fb [2] a6 fb [2] 99 e7 }

  condition:
    any of them
}