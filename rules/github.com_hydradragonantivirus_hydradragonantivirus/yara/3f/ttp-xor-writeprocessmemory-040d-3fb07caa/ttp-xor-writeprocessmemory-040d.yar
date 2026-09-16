rule TTP_XOR_WriteProcessMemory_040d {
  strings:
    $key_040d = { 53 7f [2] 61 5d [2] 67 68 [2] 49 68 [2] 76 74 }

  condition:
    any of them
}