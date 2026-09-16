rule TTP_XOR_WriteProcessMemory_212c {
  strings:
    $key_212c = { 76 5e [2] 44 7c [2] 42 49 [2] 6c 49 [2] 53 55 }

  condition:
    any of them
}