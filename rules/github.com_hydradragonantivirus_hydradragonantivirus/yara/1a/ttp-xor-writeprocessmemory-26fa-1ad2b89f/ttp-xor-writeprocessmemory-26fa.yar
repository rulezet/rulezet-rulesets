rule TTP_XOR_WriteProcessMemory_26fa {
  strings:
    $key_26fa = { 71 88 [2] 43 aa [2] 45 9f [2] 6b 9f [2] 54 83 }

  condition:
    any of them
}