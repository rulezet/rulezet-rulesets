rule TTP_XOR_WriteProcessMemory_092e {
  strings:
    $key_092e = { 5e 5c [2] 6c 7e [2] 6a 4b [2] 44 4b [2] 7b 57 }

  condition:
    any of them
}