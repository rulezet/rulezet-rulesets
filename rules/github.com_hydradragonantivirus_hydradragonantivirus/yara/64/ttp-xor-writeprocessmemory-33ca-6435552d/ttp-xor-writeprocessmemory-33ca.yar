rule TTP_XOR_WriteProcessMemory_33ca {
  strings:
    $key_33ca = { 64 b8 [2] 56 9a [2] 50 af [2] 7e af [2] 41 b3 }

  condition:
    any of them
}