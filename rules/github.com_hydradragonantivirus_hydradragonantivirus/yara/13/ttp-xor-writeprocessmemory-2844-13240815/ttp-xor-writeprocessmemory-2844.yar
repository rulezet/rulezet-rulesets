rule TTP_XOR_WriteProcessMemory_2844 {
  strings:
    $key_2844 = { 7f 36 [2] 4d 14 [2] 4b 21 [2] 65 21 [2] 5a 3d }

  condition:
    any of them
}