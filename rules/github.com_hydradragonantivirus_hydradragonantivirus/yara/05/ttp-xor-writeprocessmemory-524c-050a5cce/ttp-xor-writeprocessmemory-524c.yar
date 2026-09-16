rule TTP_XOR_WriteProcessMemory_524c {
  strings:
    $key_524c = { 05 3e [2] 37 1c [2] 31 29 [2] 1f 29 [2] 20 35 }

  condition:
    any of them
}