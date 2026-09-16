rule TTP_XOR_WriteProcessMemory_050a {
  strings:
    $key_050a = { 52 78 [2] 60 5a [2] 66 6f [2] 48 6f [2] 77 73 }

  condition:
    any of them
}