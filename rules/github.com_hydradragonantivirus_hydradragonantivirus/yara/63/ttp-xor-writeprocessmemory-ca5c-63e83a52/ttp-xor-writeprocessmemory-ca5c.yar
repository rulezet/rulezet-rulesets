rule TTP_XOR_WriteProcessMemory_ca5c {
  strings:
    $key_ca5c = { 9d 2e [2] af 0c [2] a9 39 [2] 87 39 [2] b8 25 }

  condition:
    any of them
}