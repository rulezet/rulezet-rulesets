rule TTP_XOR_WriteProcessMemory_dafd {
  strings:
    $key_dafd = { 8d 8f [2] bf ad [2] b9 98 [2] 97 98 [2] a8 84 }

  condition:
    any of them
}