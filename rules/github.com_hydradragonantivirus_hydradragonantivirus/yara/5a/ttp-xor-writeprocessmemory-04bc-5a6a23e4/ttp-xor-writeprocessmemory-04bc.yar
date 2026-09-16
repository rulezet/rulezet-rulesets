rule TTP_XOR_WriteProcessMemory_04bc {
  strings:
    $key_04bc = { 53 ce [2] 61 ec [2] 67 d9 [2] 49 d9 [2] 76 c5 }

  condition:
    any of them
}