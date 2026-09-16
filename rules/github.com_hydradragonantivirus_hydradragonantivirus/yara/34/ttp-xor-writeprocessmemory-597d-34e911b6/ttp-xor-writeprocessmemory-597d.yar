rule TTP_XOR_WriteProcessMemory_597d {
  strings:
    $key_597d = { 0e 0f [2] 3c 2d [2] 3a 18 [2] 14 18 [2] 2b 04 }

  condition:
    any of them
}