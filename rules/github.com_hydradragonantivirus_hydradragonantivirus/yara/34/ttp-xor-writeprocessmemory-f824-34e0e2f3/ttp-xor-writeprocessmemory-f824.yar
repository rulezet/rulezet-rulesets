rule TTP_XOR_WriteProcessMemory_f824 {
  strings:
    $key_f824 = { af 56 [2] 9d 74 [2] 9b 41 [2] b5 41 [2] 8a 5d }

  condition:
    any of them
}