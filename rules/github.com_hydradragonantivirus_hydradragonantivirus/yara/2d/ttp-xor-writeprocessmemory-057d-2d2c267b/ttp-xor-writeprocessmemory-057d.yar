rule TTP_XOR_WriteProcessMemory_057d {
  strings:
    $key_057d = { 52 0f [2] 60 2d [2] 66 18 [2] 48 18 [2] 77 04 }

  condition:
    any of them
}