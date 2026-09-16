rule TTP_XOR_WriteProcessMemory_789a {
  strings:
    $key_789a = { 2f e8 [2] 1d ca [2] 1b ff [2] 35 ff [2] 0a e3 }

  condition:
    any of them
}