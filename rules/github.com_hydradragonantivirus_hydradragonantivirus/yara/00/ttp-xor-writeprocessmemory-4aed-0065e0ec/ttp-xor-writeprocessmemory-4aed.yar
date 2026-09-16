rule TTP_XOR_WriteProcessMemory_4aed {
  strings:
    $key_4aed = { 1d 9f [2] 2f bd [2] 29 88 [2] 07 88 [2] 38 94 }

  condition:
    any of them
}