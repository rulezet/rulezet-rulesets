rule TTP_XOR_WriteProcessMemory_0154 {
  strings:
    $key_0154 = { 56 26 [2] 64 04 [2] 62 31 [2] 4c 31 [2] 73 2d }

  condition:
    any of them
}