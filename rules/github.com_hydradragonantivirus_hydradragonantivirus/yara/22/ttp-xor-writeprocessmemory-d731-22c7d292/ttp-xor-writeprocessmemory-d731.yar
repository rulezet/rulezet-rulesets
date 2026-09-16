rule TTP_XOR_WriteProcessMemory_d731 {
  strings:
    $key_d731 = { 80 43 [2] b2 61 [2] b4 54 [2] 9a 54 [2] a5 48 }

  condition:
    any of them
}