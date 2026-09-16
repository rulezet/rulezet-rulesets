rule TTP_XOR_WriteProcessMemory_14bc {
  strings:
    $key_14bc = { 43 ce [2] 71 ec [2] 77 d9 [2] 59 d9 [2] 66 c5 }

  condition:
    any of them
}