rule TTP_XOR_WriteProcessMemory_28ab {
  strings:
    $key_28ab = { 7f d9 [2] 4d fb [2] 4b ce [2] 65 ce [2] 5a d2 }

  condition:
    any of them
}