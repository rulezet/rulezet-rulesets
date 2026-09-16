rule TTP_XOR_WriteProcessMemory_faed {
  strings:
    $key_faed = { ad 9f [2] 9f bd [2] 99 88 [2] b7 88 [2] 88 94 }

  condition:
    any of them
}