rule TTP_XOR_WriteProcessMemory_fbfb {
  strings:
    $key_fbfb = { ac 89 [2] 9e ab [2] 98 9e [2] b6 9e [2] 89 82 }

  condition:
    any of them
}