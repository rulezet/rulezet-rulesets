rule TTP_XOR_WriteProcessMemory_db93 {
  strings:
    $key_db93 = { 8c e1 [2] be c3 [2] b8 f6 [2] 96 f6 [2] a9 ea }

  condition:
    any of them
}