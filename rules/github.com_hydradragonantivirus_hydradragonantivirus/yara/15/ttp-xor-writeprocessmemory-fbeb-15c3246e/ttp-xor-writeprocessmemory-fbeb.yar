rule TTP_XOR_WriteProcessMemory_fbeb {
  strings:
    $key_fbeb = { ac 99 [2] 9e bb [2] 98 8e [2] b6 8e [2] 89 92 }

  condition:
    any of them
}