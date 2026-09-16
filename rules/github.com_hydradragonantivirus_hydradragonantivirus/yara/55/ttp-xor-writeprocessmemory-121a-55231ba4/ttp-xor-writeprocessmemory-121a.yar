rule TTP_XOR_WriteProcessMemory_121a {
  strings:
    $key_121a = { 45 68 [2] 77 4a [2] 71 7f [2] 5f 7f [2] 60 63 }

  condition:
    any of them
}