rule TTP_XOR_WriteProcessMemory_015c {
  strings:
    $key_015c = { 56 2e [2] 64 0c [2] 62 39 [2] 4c 39 [2] 73 25 }

  condition:
    any of them
}