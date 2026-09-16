rule TTP_XOR_WriteProcessMemory_cd9e {
  strings:
    $key_cd9e = { 9a ec [2] a8 ce [2] ae fb [2] 80 fb [2] bf e7 }

  condition:
    any of them
}