rule TTP_XOR_WriteProcessMemory_24b2 {
  strings:
    $key_24b2 = { 73 c0 [2] 41 e2 [2] 47 d7 [2] 69 d7 [2] 56 cb }

  condition:
    any of them
}