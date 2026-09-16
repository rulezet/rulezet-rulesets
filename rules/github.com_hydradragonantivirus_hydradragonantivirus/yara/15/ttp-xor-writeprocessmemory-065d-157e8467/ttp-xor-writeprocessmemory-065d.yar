rule TTP_XOR_WriteProcessMemory_065d {
  strings:
    $key_065d = { 51 2f [2] 63 0d [2] 65 38 [2] 4b 38 [2] 74 24 }

  condition:
    any of them
}