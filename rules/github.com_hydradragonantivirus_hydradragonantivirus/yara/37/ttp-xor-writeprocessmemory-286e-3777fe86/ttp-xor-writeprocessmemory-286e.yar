rule TTP_XOR_WriteProcessMemory_286e {
  strings:
    $key_286e = { 7f 1c [2] 4d 3e [2] 4b 0b [2] 65 0b [2] 5a 17 }

  condition:
    any of them
}