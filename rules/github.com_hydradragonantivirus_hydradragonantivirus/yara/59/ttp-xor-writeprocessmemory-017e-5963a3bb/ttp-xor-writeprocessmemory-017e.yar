rule TTP_XOR_WriteProcessMemory_017e {
  strings:
    $key_017e = { 56 0c [2] 64 2e [2] 62 1b [2] 4c 1b [2] 73 07 }

  condition:
    any of them
}