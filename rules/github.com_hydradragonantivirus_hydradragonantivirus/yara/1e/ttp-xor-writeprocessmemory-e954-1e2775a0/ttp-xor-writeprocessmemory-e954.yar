rule TTP_XOR_WriteProcessMemory_e954 {
  strings:
    $key_e954 = { be 26 [2] 8c 04 [2] 8a 31 [2] a4 31 [2] 9b 2d }

  condition:
    any of them
}