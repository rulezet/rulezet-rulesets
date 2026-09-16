rule TTP_XOR_WriteProcessMemory_fa54 {
  strings:
    $key_fa54 = { ad 26 [2] 9f 04 [2] 99 31 [2] b7 31 [2] 88 2d }

  condition:
    any of them
}