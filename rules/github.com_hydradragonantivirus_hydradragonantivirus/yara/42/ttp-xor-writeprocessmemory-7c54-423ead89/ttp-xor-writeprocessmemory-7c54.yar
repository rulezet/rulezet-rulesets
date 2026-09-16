rule TTP_XOR_WriteProcessMemory_7c54 {
  strings:
    $key_7c54 = { 2b 26 [2] 19 04 [2] 1f 31 [2] 31 31 [2] 0e 2d }

  condition:
    any of them
}