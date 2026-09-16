rule TTP_XOR_WriteProcessMemory_05e3 {
  strings:
    $key_05e3 = { 52 91 [2] 60 b3 [2] 66 86 [2] 48 86 [2] 77 9a }

  condition:
    any of them
}