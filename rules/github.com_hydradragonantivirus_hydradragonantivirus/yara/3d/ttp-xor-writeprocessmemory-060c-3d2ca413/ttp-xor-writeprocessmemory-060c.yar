rule TTP_XOR_WriteProcessMemory_060c {
  strings:
    $key_060c = { 51 7e [2] 63 5c [2] 65 69 [2] 4b 69 [2] 74 75 }

  condition:
    any of them
}