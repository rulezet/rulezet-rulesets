rule TTP_XOR_WriteProcessMemory_054c {
  strings:
    $key_054c = { 52 3e [2] 60 1c [2] 66 29 [2] 48 29 [2] 77 35 }

  condition:
    any of them
}