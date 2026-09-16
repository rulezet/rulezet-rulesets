rule TTP_XOR_WriteProcessMemory_f810 {
  strings:
    $key_f810 = { af 62 [2] 9d 40 [2] 9b 75 [2] b5 75 [2] 8a 69 }

  condition:
    any of them
}