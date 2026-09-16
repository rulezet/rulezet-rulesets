rule TTP_XOR_WriteProcessMemory_050d {
  strings:
    $key_050d = { 52 7f [2] 60 5d [2] 66 68 [2] 48 68 [2] 77 74 }

  condition:
    any of them
}