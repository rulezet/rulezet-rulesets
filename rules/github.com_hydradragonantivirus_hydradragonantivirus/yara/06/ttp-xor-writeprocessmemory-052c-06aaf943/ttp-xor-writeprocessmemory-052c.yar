rule TTP_XOR_WriteProcessMemory_052c {
  strings:
    $key_052c = { 52 5e [2] 60 7c [2] 66 49 [2] 48 49 [2] 77 55 }

  condition:
    any of them
}