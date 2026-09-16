rule TTP_XOR_WriteProcessMemory_036a {
  strings:
    $key_036a = { 54 18 [2] 66 3a [2] 60 0f [2] 4e 0f [2] 71 13 }

  condition:
    any of them
}