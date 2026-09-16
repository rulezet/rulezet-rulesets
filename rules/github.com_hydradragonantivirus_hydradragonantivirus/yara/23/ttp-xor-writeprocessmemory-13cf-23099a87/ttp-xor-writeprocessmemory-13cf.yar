rule TTP_XOR_WriteProcessMemory_13cf {
  strings:
    $key_13cf = { 44 bd [2] 76 9f [2] 70 aa [2] 5e aa [2] 61 b6 }

  condition:
    any of them
}