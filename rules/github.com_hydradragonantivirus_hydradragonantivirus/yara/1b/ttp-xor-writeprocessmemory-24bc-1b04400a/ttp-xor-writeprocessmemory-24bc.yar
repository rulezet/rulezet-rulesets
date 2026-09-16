rule TTP_XOR_WriteProcessMemory_24bc {
  strings:
    $key_24bc = { 73 ce [2] 41 ec [2] 47 d9 [2] 69 d9 [2] 56 c5 }

  condition:
    any of them
}