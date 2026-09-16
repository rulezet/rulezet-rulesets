rule TTP_XOR_WriteProcessMemory_ad82 {
  strings:
    $key_ad82 = { fa f0 [2] c8 d2 [2] ce e7 [2] e0 e7 [2] df fb }

  condition:
    any of them
}