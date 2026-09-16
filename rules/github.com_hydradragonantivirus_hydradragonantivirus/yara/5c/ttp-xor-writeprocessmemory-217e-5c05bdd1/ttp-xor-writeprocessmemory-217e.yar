rule TTP_XOR_WriteProcessMemory_217e {
  strings:
    $key_217e = { 76 0c [2] 44 2e [2] 42 1b [2] 6c 1b [2] 53 07 }

  condition:
    any of them
}