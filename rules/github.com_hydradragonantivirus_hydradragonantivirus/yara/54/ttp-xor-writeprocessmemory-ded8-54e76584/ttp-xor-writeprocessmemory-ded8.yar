rule TTP_XOR_WriteProcessMemory_ded8 {
  strings:
    $key_ded8 = { 89 aa [2] bb 88 [2] bd bd [2] 93 bd [2] ac a1 }

  condition:
    any of them
}