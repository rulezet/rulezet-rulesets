rule TTP_XOR_WriteProcessMemory_19b3 {
  strings:
    $key_19b3 = { 4e c1 [2] 7c e3 [2] 7a d6 [2] 54 d6 [2] 6b ca }

  condition:
    any of them
}