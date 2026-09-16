rule TTP_XOR_WriteProcessMemory_61ec {
  strings:
    $key_61ec = { 36 9e [2] 04 bc [2] 02 89 [2] 2c 89 [2] 13 95 }

  condition:
    any of them
}