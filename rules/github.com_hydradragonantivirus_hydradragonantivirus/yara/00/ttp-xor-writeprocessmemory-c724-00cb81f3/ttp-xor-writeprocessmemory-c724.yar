rule TTP_XOR_WriteProcessMemory_c724 {
  strings:
    $key_c724 = { 90 56 [2] a2 74 [2] a4 41 [2] 8a 41 [2] b5 5d }

  condition:
    any of them
}