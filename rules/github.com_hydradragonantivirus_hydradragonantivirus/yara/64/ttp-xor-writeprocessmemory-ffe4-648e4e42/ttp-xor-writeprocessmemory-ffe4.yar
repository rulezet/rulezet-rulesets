rule TTP_XOR_WriteProcessMemory_ffe4 {
  strings:
    $key_ffe4 = { a8 96 [2] 9a b4 [2] 9c 81 [2] b2 81 [2] 8d 9d }

  condition:
    any of them
}