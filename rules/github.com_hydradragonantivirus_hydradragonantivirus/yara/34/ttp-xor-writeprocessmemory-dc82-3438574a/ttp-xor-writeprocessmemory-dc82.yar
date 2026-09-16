rule TTP_XOR_WriteProcessMemory_dc82 {
  strings:
    $key_dc82 = { 8b f0 [2] b9 d2 [2] bf e7 [2] 91 e7 [2] ae fb }

  condition:
    any of them
}