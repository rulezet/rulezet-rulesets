rule TTP_XOR_WriteProcessMemory_f989 {
  strings:
    $key_f989 = { ae fb [2] 9c d9 [2] 9a ec [2] b4 ec [2] 8b f0 }

  condition:
    any of them
}