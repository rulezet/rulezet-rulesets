rule TTP_XOR_WriteProcessMemory_120a {
  strings:
    $key_120a = { 45 78 [2] 77 5a [2] 71 6f [2] 5f 6f [2] 60 73 }

  condition:
    any of them
}