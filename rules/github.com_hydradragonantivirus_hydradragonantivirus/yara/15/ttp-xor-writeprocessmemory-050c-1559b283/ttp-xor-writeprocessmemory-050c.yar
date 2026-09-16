rule TTP_XOR_WriteProcessMemory_050c {
  strings:
    $key_050c = { 52 7e [2] 60 5c [2] 66 69 [2] 48 69 [2] 77 75 }

  condition:
    any of them
}