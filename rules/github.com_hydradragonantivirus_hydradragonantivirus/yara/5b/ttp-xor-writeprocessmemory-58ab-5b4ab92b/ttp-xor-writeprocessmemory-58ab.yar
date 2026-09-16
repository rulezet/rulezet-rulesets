rule TTP_XOR_WriteProcessMemory_58ab {
  strings:
    $key_58ab = { 0f d9 [2] 3d fb [2] 3b ce [2] 15 ce [2] 2a d2 }

  condition:
    any of them
}