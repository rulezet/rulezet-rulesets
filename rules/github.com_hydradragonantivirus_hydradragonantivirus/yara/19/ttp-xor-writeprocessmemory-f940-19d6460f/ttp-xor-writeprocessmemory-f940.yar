rule TTP_XOR_WriteProcessMemory_f940 {
  strings:
    $key_f940 = { ae 32 [2] 9c 10 [2] 9a 25 [2] b4 25 [2] 8b 39 }

  condition:
    any of them
}