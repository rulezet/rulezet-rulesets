rule TTP_XOR_WriteProcessMemory_162c {
  strings:
    $key_162c = { 41 5e [2] 73 7c [2] 75 49 [2] 5b 49 [2] 64 55 }

  condition:
    any of them
}