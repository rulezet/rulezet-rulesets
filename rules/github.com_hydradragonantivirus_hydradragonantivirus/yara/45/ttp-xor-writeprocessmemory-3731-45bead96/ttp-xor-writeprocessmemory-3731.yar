rule TTP_XOR_WriteProcessMemory_3731 {
  strings:
    $key_3731 = { 60 43 [2] 52 61 [2] 54 54 [2] 7a 54 [2] 45 48 }

  condition:
    any of them
}