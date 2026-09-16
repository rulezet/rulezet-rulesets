rule TTP_XOR_WriteProcessMemory_126a {
  strings:
    $key_126a = { 45 18 [2] 77 3a [2] 71 0f [2] 5f 0f [2] 60 13 }

  condition:
    any of them
}