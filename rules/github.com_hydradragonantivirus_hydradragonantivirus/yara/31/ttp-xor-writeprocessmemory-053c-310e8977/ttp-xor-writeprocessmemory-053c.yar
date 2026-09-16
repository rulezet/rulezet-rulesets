rule TTP_XOR_WriteProcessMemory_053c {
  strings:
    $key_053c = { 52 4e [2] 60 6c [2] 66 59 [2] 48 59 [2] 77 45 }

  condition:
    any of them
}