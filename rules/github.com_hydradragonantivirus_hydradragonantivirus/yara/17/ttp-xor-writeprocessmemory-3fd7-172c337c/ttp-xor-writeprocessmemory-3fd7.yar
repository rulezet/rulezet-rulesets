rule TTP_XOR_WriteProcessMemory_3fd7 {
  strings:
    $key_3fd7 = { 68 a5 [2] 5a 87 [2] 5c b2 [2] 72 b2 [2] 4d ae }

  condition:
    any of them
}