rule TTP_XOR_WriteProcessMemory_daed {
  strings:
    $key_daed = { 8d 9f [2] bf bd [2] b9 88 [2] 97 88 [2] a8 94 }

  condition:
    any of them
}