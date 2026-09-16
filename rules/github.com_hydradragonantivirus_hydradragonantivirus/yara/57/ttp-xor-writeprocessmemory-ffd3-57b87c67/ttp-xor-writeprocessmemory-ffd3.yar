rule TTP_XOR_WriteProcessMemory_ffd3 {
  strings:
    $key_ffd3 = { a8 a1 [2] 9a 83 [2] 9c b6 [2] b2 b6 [2] 8d aa }

  condition:
    any of them
}