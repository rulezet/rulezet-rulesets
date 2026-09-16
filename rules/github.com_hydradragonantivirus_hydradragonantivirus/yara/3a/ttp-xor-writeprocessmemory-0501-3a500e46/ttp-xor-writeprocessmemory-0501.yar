rule TTP_XOR_WriteProcessMemory_0501 {
  strings:
    $key_0501 = { 52 73 [2] 60 51 [2] 66 64 [2] 48 64 [2] 77 78 }

  condition:
    any of them
}