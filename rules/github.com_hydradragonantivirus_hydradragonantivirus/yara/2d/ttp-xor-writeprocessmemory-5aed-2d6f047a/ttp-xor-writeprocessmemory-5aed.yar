rule TTP_XOR_WriteProcessMemory_5aed {
  strings:
    $key_5aed = { 0d 9f [2] 3f bd [2] 39 88 [2] 17 88 [2] 28 94 }

  condition:
    any of them
}