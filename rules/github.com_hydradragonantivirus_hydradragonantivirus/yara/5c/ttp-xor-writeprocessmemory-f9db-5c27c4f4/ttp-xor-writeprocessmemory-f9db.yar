rule TTP_XOR_WriteProcessMemory_f9db {
  strings:
    $key_f9db = { ae a9 [2] 9c 8b [2] 9a be [2] b4 be [2] 8b a2 }

  condition:
    any of them
}