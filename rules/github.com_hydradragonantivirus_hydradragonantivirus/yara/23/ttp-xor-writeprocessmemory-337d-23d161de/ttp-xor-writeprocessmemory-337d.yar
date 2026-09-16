rule TTP_XOR_WriteProcessMemory_337d {
  strings:
    $key_337d = { 64 0f [2] 56 2d [2] 50 18 [2] 7e 18 [2] 41 04 }

  condition:
    any of them
}