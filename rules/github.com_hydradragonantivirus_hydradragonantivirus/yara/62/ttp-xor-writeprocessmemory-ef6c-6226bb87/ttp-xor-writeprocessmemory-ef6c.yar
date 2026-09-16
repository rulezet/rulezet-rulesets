rule TTP_XOR_WriteProcessMemory_ef6c {
  strings:
    $key_ef6c = { b8 1e [2] 8a 3c [2] 8c 09 [2] a2 09 [2] 9d 15 }

  condition:
    any of them
}