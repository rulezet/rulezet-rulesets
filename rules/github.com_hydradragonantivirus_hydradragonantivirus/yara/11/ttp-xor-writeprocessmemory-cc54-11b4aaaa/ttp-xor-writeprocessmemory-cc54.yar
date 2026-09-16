rule TTP_XOR_WriteProcessMemory_cc54 {
  strings:
    $key_cc54 = { 9b 26 [2] a9 04 [2] af 31 [2] 81 31 [2] be 2d }

  condition:
    any of them
}