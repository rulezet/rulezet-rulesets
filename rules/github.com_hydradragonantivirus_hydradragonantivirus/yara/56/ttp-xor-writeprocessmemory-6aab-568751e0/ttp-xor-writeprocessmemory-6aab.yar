rule TTP_XOR_WriteProcessMemory_6aab {
  strings:
    $key_6aab = { 3d d9 [2] 0f fb [2] 09 ce [2] 27 ce [2] 18 d2 }

  condition:
    any of them
}