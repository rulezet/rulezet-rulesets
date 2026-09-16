rule TTP_XOR_WriteProcessMemory_09b2 {
  strings:
    $key_09b2 = { 5e c0 [2] 6c e2 [2] 6a d7 [2] 44 d7 [2] 7b cb }

  condition:
    any of them
}