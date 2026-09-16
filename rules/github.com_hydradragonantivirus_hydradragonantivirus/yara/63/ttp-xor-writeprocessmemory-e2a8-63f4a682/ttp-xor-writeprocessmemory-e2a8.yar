rule TTP_XOR_WriteProcessMemory_e2a8 {
  strings:
    $key_e2a8 = { b5 da [2] 87 f8 [2] 81 cd [2] af cd [2] 90 d1 }

  condition:
    any of them
}