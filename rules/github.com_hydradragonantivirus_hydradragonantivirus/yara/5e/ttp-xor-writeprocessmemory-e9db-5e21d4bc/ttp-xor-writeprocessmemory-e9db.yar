rule TTP_XOR_WriteProcessMemory_e9db {
  strings:
    $key_e9db = { be a9 [2] 8c 8b [2] 8a be [2] a4 be [2] 9b a2 }

  condition:
    any of them
}