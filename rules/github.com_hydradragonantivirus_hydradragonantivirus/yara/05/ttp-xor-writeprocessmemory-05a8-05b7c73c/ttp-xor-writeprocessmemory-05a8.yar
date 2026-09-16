rule TTP_XOR_WriteProcessMemory_05a8 {
  strings:
    $key_05a8 = { 52 da [2] 60 f8 [2] 66 cd [2] 48 cd [2] 77 d1 }

  condition:
    any of them
}